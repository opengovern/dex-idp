// server/platform/service/tokens.go
package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log" // TODO: Replace with Dex structured logger if available
	"strconv"
	"strings"
	"time"

	// Ent imports
	"github.com/dexidp/dex/storage/ent/db" // Generated Ent client package, defines error types

	// Dex storage interface & potentially helpers
	pstorage "github.com/dexidp/dex/server/platform/storage"
	// platformsql "github.com/dexidp/dex/storage/sql" // Only needed if using helpers from there directly

	// Token generation/verification utilities
	tokenutils "github.com/dexidp/dex/server/platform/tokenutils" // Adjust import path as needed

	// gRPC & Protobuf
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	// Dex API
	api "github.com/dexidp/dex/api/v2"

	// LibPQ for error checking (optional but helpful)
	"github.com/lib/pq"
)

// platformTokenService implements the api.PlatformTokenServiceServer interface.
type platformTokenService struct {
	api.UnimplementedPlatformTokenServiceServer
	storage pstorage.PlatformStorage // Depends on the combined storage interface
	// logger dexlogger.Logger // Add logger field here
}

// NewPlatformTokenService creates a new handler for the PlatformTokenService.
func NewPlatformTokenService(storage pstorage.PlatformStorage) api.PlatformTokenServiceServer {
	if storage == nil {
		log.Fatal("PlatformStorage cannot be nil for PlatformTokenService")
	}
	return &platformTokenService{storage: storage}
}

// CreatePlatformToken handles the RPC call to create a new platform token.
func (s *platformTokenService) CreatePlatformToken(ctx context.Context, req *api.CreatePlatformTokenRequest) (*api.CreatePlatformTokenResponse, error) {
	// 1. Validate input IDs
	if req.GetOwnerId() == "" || req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "owner_id and role_id are required")
	}
	ownerID, err := stringIDToInt(req.GetOwnerId()) // Use helper
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid owner_id format: %v", err)
	}
	roleID, err := stringIDToInt(req.GetRoleId()) // Use helper
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id format: %v", err)
	}

	// 2. Generate token components
	prefix := ""
	if pfx := req.GetPublicIdPrefix(); pfx != nil {
		prefix = pfx.GetValue()
		// TODO: Add validation for allowed prefix formats if needed
	}
	publicID, err := tokenutils.GeneratePublicID(prefix)
	if err != nil {
		log.Printf("ERROR: CreatePlatformToken - failed to generate public ID: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate token identifier")
	}

	secret, err := tokenutils.GenerateTokenSecret(32) // Generate 32 random bytes for the secret
	if err != nil {
		log.Printf("ERROR: CreatePlatformToken - failed to generate secret: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate token secret")
	}

	// 3. Hash the secret
	encodedHash, err := tokenutils.HashSecret(secret)
	if err != nil {
		log.Printf("ERROR: CreatePlatformToken - failed to hash secret: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to hash token secret")
	}

	// 4. Prepare data for storage
	tokenData := &db.PlatformToken{
		OwnerID:    ownerID, // Set explicit owner_id field
		PublicID:   publicID,
		SecretHash: encodedHash, // Store the encoded hash string
		IsActive:   true,        // New tokens default to active
		// RoleID is not a field on the struct, pass separately
	}
	// Handle optional expiry
	if req.ExpiresAt != nil {
		if err := req.ExpiresAt.CheckValid(); err == nil {
			expiresAtTime := req.ExpiresAt.AsTime()
			// Optional: Add validation that expiry is in the future?
			// if expiresAtTime.Before(time.Now()) {
			// 	 return nil, status.Errorf(codes.InvalidArgument, "expires_at cannot be in the past")
			// }
			tokenData.ExpiresAt = &expiresAtTime
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "invalid expires_at timestamp: %v", err)
		}
	}

	// 5. Store the token using the storage interface
	// Pass roleID as separate arg now
	createdToken, err := s.storage.CreateToken(ctx, tokenData, roleID)
	if err != nil {
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && (pqErr.Code == "23505" || pqErr.Code == "23503")) {
			// 23505 = unique violation (likely public_id)
			// 23503 = foreign key violation (owner_id or role_id doesn't exist)
			log.Printf("INFO: CreatePlatformToken - constraint violation owner=%d, role=%d: %v", ownerID, roleID, err)
			if errors.As(err, &pqErr) && pqErr.Code == "23503" {
				return nil, status.Errorf(codes.FailedPrecondition, "invalid owner or role specified")
			}
			return nil, status.Errorf(codes.AlreadyExists, "token constraint violation (e.g., duplicate public ID)")
		}
		log.Printf("ERROR: CreatePlatformToken - storage error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to store token")
	}

	// 6. Convert created token to proto for response (edges loaded by CreateToken->GetTokenByID)
	protoToken := toProtoPlatformToken(createdToken)
	if protoToken == nil {
		log.Printf("ERROR: CreatePlatformToken - failed conversion for token ID %d", createdToken.ID)
		// Don't fail the whole request, but maybe log? The essential parts are returned below.
		// We can construct a minimal PlatformToken message if conversion fails partially.
		// For now, rely on helper returning nil. The response requires the message.
		return nil, status.Error(codes.Internal, "failed to process created token data")
	}

	// 7. Return the response including the raw secret
	return &api.CreatePlatformTokenResponse{
		PlatformToken: protoToken,
		Secret:        secret, // The raw, unhashed secret
	}, nil
}

// GetPlatformToken handles retrieving token details by internal ID.
func (s *platformTokenService) GetPlatformToken(ctx context.Context, req *api.GetPlatformTokenRequest) (*api.GetPlatformTokenResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token ID cannot be empty")
	}
	tokenID, err := strconv.Atoi(req.GetId())
	if err != nil || tokenID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid token ID format: %s", req.GetId())
	}
	// TODO: Authorization check - who can get token details? Owner? Admin?

	entToken, err := s.storage.GetTokenByID(ctx, tokenID)
	if err != nil {
		var nfe *db.NotFoundError
		if errors.As(err, &nfe) {
			log.Printf("INFO: GetPlatformToken - token not found for ID %d", tokenID)
			return nil, status.Errorf(codes.NotFound, "token with ID '%s' not found", req.GetId())
		}
		log.Printf("ERROR: GetPlatformToken - storage error getting ID %d: %v", tokenID, err)
		return nil, status.Errorf(codes.Internal, "failed to get token")
	}

	protoToken := toProtoPlatformToken(entToken)
	if protoToken == nil {
		log.Printf("ERROR: GetPlatformToken - failed to convert token (ID: %d) to proto", tokenID)
		return nil, status.Errorf(codes.Internal, "failed to process token data")
	}

	return &api.GetPlatformTokenResponse{PlatformToken: protoToken}, nil
}

// ListPlatformTokens handles listing tokens with pagination and filtering.
func (s *platformTokenService) ListPlatformTokens(ctx context.Context, req *api.ListPlatformTokensRequest) (*api.ListPlatformTokensResponse, error) {
	// --- Pagination Setup ---
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	var cursorTime *time.Time
	var cursorID *int
	if req.GetPageToken() != "" {
		decodedTime, decodedID, err := decodeTokenPageToken(req.GetPageToken()) // Use token-specific decoder
		if err != nil {
			log.Printf("WARN: ListPlatformTokens - invalid page token: %v", err)
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token: %v", err)
		}
		cursorTime = &decodedTime
		cursorID = &decodedID
	}

	// --- Prepare Filters ---
	filters := pstorage.TokenFilters{}
	if ownerID := req.GetFilterOwnerId(); ownerID != "" {
		// Validate owner ID format? stringIDToInt does basic check.
		if _, err := stringIDToInt(ownerID); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid filter_owner_id format: %v", err)
		}
		filters.OwnerID = ownerID
	}
	if roleID := req.GetFilterAppRoleId(); roleID != "" {
		if _, err := stringIDToInt(roleID); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid filter_app_role_id format: %v", err)
		}
		filters.AppRoleID = roleID
	}
	if filter := req.GetFilterIsActive(); filter != nil {
		tmpBool := filter.GetValue()
		filters.IsActive = &tmpBool
	}
	if filter := req.GetFilterExcludeExpired(); filter != nil {
		filters.ExcludeExpired = filter.GetValue()
	}
	// TODO: Authorization check - maybe only list tokens owned by caller? Or filter by tenant?

	// --- Execute Paginated List Query ---
	limit := pageSize + 1 // Fetch one extra
	entTokens, err := s.storage.ListTokensPaginated(ctx, limit, cursorTime, cursorID, filters)
	if err != nil {
		log.Printf("ERROR: ListPlatformTokens - storage error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list tokens")
	}

	// --- Determine Next Page Token ---
	hasNextPage := false
	if len(entTokens) > pageSize {
		hasNextPage = true
		entTokens = entTokens[:pageSize] // Trim extra item
	}

	nextPageToken := ""
	if hasNextPage && len(entTokens) > 0 {
		lastToken := entTokens[len(entTokens)-1]
		encodedToken, errEnc := encodeTokenPageToken(*lastToken) // Use token-specific encoder
		if errEnc != nil {
			log.Printf("ERROR: ListPlatformTokens - failed to encode next page token for token ID %d: %v", lastToken.ID, errEnc)
		} else {
			nextPageToken = encodedToken
		}
	}

	// --- Convert Results to Protobuf ---
	protoTokens := make([]*api.PlatformToken, 0, len(entTokens))
	for _, entToken := range entTokens {
		protoToken := toProtoPlatformToken(entToken)
		if protoToken != nil {
			protoTokens = append(protoTokens, protoToken)
		} else {
			log.Printf("WARN: ListPlatformTokens - failed to convert token (ID: %d) to proto", entToken.ID)
		}
	}

	// --- Return Response ---
	return &api.ListPlatformTokensResponse{
		Tokens:        protoTokens,
		NextPageToken: nextPageToken,
		// TotalSize removed
	}, nil
}

// UpdatePlatformToken handles updating ONLY the role of a token.
func (s *platformTokenService) UpdatePlatformToken(ctx context.Context, req *api.UpdatePlatformTokenRequest) (*api.UpdatePlatformTokenResponse, error) {
	if req.GetId() == "" || req.GetNewRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "token ID and new_role_id are required")
	}
	tokenID, err := strconv.Atoi(req.GetId())
	if err != nil || tokenID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid token ID format: %s", req.GetId())
	}
	newRoleID, err := strconv.Atoi(req.GetNewRoleId())
	if err != nil || newRoleID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid new_role_id format: %s", req.GetNewRoleId())
	}
	// TODO: Authorization check - who can update token roles? Owner? Admin?

	updatedEntToken, err := s.storage.UpdateTokenRole(ctx, tokenID, newRoleID)
	if err != nil {
		var nfe *db.NotFoundError
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &nfe) {
			log.Printf("INFO: UpdatePlatformToken - token not found for ID %d", tokenID)
			return nil, status.Errorf(codes.NotFound, "token with ID '%s' not found", req.GetId())
		} else if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && pqErr.Code == "23503") {
			// Foreign key violation (newRoleID likely doesn't exist)
			log.Printf("INFO: UpdatePlatformToken - invalid new role ID %d for token %d", newRoleID, tokenID)
			return nil, status.Errorf(codes.FailedPrecondition, "invalid new role ID specified: %s", req.GetNewRoleId())
		}
		log.Printf("ERROR: UpdatePlatformToken - storage error updating token ID %d: %v", tokenID, err)
		return nil, status.Errorf(codes.Internal, "failed to update token role")
	}

	protoToken := toProtoPlatformToken(updatedEntToken)
	if protoToken == nil {
		log.Printf("ERROR: UpdatePlatformToken - failed converting updated token (ID: %d) to proto", tokenID)
		return nil, status.Errorf(codes.Internal, "failed to process updated token data")
	}

	return &api.UpdatePlatformTokenResponse{PlatformToken: protoToken}, nil
}

// DeletePlatformToken handles deleting a token by its internal ID.
func (s *platformTokenService) DeletePlatformToken(ctx context.Context, req *api.DeletePlatformTokenRequest) (*emptypb.Empty, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token ID cannot be empty")
	}
	tokenID, err := strconv.Atoi(req.GetId())
	if err != nil || tokenID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid token ID format: %s", req.GetId())
	}
	// TODO: Authorization check - who can delete tokens? Owner? Admin?

	err = s.storage.DeleteTokenByID(ctx, tokenID)
	if err != nil {
		var nfe *db.NotFoundError
		if errors.As(err, &nfe) {
			log.Printf("INFO: DeletePlatformToken - token not found for ID %d", tokenID)
			return nil, status.Errorf(codes.NotFound, "token with ID '%s' not found", req.GetId())
		}
		log.Printf("ERROR: DeletePlatformToken - storage error deleting ID %d: %v", tokenID, err)
		return nil, status.Errorf(codes.Internal, "failed to delete token")
	}

	log.Printf("INFO: Successfully deleted token ID %d", tokenID)
	return &emptypb.Empty{}, nil
}

// VerifyPlatformToken handles checking if a provided secret matches the stored hash for a public ID.
func (s *platformTokenService) VerifyPlatformToken(ctx context.Context, req *api.VerifyPlatformTokenRequest) (*api.VerifyPlatformTokenResponse, error) {
	if req.GetPublicId() == "" || req.GetSecret() == "" {
		return nil, status.Error(codes.InvalidArgument, "public_id and secret are required")
	}

	// 1. Fetch token by public ID
	entToken, err := s.storage.GetTokenByPublicID(ctx, req.GetPublicId())
	if err != nil {
		var nfe *db.NotFoundError
		if errors.As(err, &nfe) {
			// Log potentially sensitive info only internally
			log.Printf("INFO: VerifyPlatformToken - token not found for public_id %s", req.GetPublicId())
			// Return false, DO NOT indicate not found vs invalid secret to prevent enumeration
			return &api.VerifyPlatformTokenResponse{Verified: false}, nil
		}
		log.Printf("ERROR: VerifyPlatformToken - storage error getting public_id %s: %v", req.GetPublicId(), err)
		return nil, status.Errorf(codes.Internal, "token verification failed")
	}

	// 2. Check if token is active
	if !entToken.IsActive {
		log.Printf("INFO: VerifyPlatformToken - token %s (ID: %d) is inactive", req.GetPublicId(), entToken.ID)
		return &api.VerifyPlatformTokenResponse{Verified: false}, nil
	}

	// 3. Check expiry
	if entToken.ExpiresAt != nil && entToken.ExpiresAt.Before(time.Now()) {
		log.Printf("INFO: VerifyPlatformToken - token %s (ID: %d) has expired at %v", req.GetPublicId(), entToken.ID, entToken.ExpiresAt)
		return &api.VerifyPlatformTokenResponse{Verified: false}, nil
	}

	// 4. Verify secret against hash
	// Assumes tokenutils.VerifySecret(plainSecret, encodedArgon2Hash) (bool, error) exists
	verified, err := tokenutils.VerifySecret(req.GetSecret(), entToken.SecretHash)
	if err != nil {
		// This could be due to invalid hash format in DB or other Argon2 error
		log.Printf("ERROR: VerifyPlatformToken - failed to verify secret for token %s (ID: %d): %v", req.GetPublicId(), entToken.ID, err)
		// Don't expose internal error details generally, return verification failed
		return &api.VerifyPlatformTokenResponse{Verified: false}, nil
	}

	if !verified {
		log.Printf("INFO: VerifyPlatformToken - invalid secret provided for token %s (ID: %d)", req.GetPublicId(), entToken.ID)
		return &api.VerifyPlatformTokenResponse{Verified: false}, nil
	}

	// 5. Verification successful, convert to simplified Info proto
	tokenInfo := toProtoPlatformTokenInfo(entToken)
	if tokenInfo == nil {
		log.Printf("ERROR: VerifyPlatformToken - failed converting verified token (ID: %d) to proto info", entToken.ID)
		return nil, status.Errorf(codes.Internal, "failed processing verified token")
	}

	log.Printf("INFO: VerifyPlatformToken - successful verification for token %s (ID: %d)", req.GetPublicId(), entToken.ID)
	return &api.VerifyPlatformTokenResponse{
		Verified:  true,
		TokenInfo: tokenInfo,
	}, nil
}

// --- Helper Functions ---

// NOTE: Copied from users.go - consider moving to a shared internal package
// e.g., server/platform/convert or server/platform/grpcutil

// stringIDToInt converts string ID to positive integer ID.
func stringIDToInt(idStr string) (int, error) {
	if idStr == "" {
		return 0, fmt.Errorf("ID cannot be empty")
	}
	idInt64, err := strconv.ParseInt(idStr, 10, 0)
	if err != nil {
		return 0, fmt.Errorf("invalid integer ID format '%s': %w", idStr, err)
	}
	idInt := int(idInt64)
	if idInt <= 0 {
		return 0, fmt.Errorf("ID must be positive integer: received '%s'", idStr)
	}
	return idInt, nil
}

// validatePositiveID validates integer ID is positive.
func validatePositiveID(id int) error {
	if id <= 0 {
		return fmt.Errorf("ID must be positive integer: received %d", id)
	}
	return nil
}

// encodeTokenPageToken encodes cursor information for tokens.
func encodeTokenPageToken(token db.PlatformToken) (string, error) {
	if token.ID == 0 || token.CreateTime.IsZero() {
		return "", errors.New("cannot encode cursor for token with zero ID or CreateTime")
	}
	cursor := fmt.Sprintf("%d_%d", token.CreateTime.UnixNano(), token.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(cursor)), nil
}

// decodeTokenPageToken decodes a page token for tokens.
func decodeTokenPageToken(token string) (cursorTime time.Time, cursorID int, err error) {
	if token == "" {
		err = errors.New("page token is empty")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		err = fmt.Errorf("invalid page token encoding: %w", err)
		return
	}
	parts := strings.SplitN(string(decoded), "_", 2)
	if len(parts) != 2 {
		err = errors.New("invalid page token format")
		return
	}
	timeNano, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid time in page token: %w", err)
		return
	}
	cursorID, err = strconv.Atoi(parts[1])
	if err != nil || cursorID <= 0 {
		err = fmt.Errorf("invalid ID in page token: %w", err)
		return
	}
	cursorTime = time.Unix(0, timeNano).UTC()
	return
}

// toProtoPlatformToken converts an Ent *db.PlatformToken to *api.PlatformToken.
// Requires owner and role edges to be loaded on the input entToken.
func toProtoPlatformToken(entToken *db.PlatformToken) *api.PlatformToken {
	if entToken == nil {
		return nil
	}

	// Check if edges are loaded - return partial data or nil/error?
	// Returning partial seems acceptable for Get/List, but log warning.
	var owner *api.PlatformUser
	var role *api.PlatformAppRole
	if entToken.Edges.Owner != nil {
		owner = toProtoPlatformUser(entToken.Edges.Owner) // Requires this helper
	} else {
		log.Printf("WARN: toProtoPlatformToken - Owner edge not loaded for token ID %d", entToken.ID)
	}
	if entToken.Edges.Role != nil {
		role = toProtoPlatformAppRole(entToken.Edges.Role) // Requires this helper
	} else {
		log.Printf("WARN: toProtoPlatformToken - Role edge not loaded for token ID %d", entToken.ID)
	}

	proto := &api.PlatformToken{
		Id:         strconv.Itoa(entToken.ID),
		PublicId:   entToken.PublicID,
		Owner:      owner, // Assign potentially nil converted owner
		Role:       role,  // Assign potentially nil converted role
		IsActive:   entToken.IsActive,
		CreateTime: timestamppb.New(entToken.CreateTime),
		UpdateTime: timestamppb.New(entToken.UpdateTime),
	}
	if entToken.ExpiresAt != nil && !entToken.ExpiresAt.IsZero() {
		proto.ExpiresAt = timestamppb.New(*entToken.ExpiresAt)
	}
	return proto
}

// toProtoPlatformTokenInfo converts *db.PlatformToken to simpler *api.PlatformTokenInfo.
// Requires Role edge to be loaded on entToken for RoleId.
func toProtoPlatformTokenInfo(entToken *db.PlatformToken) *api.PlatformTokenInfo {
	if entToken == nil {
		return nil
	}

	ownerIDStr := ""
	// OwnerID is an explicit field, check if it's set
	if entToken.OwnerID > 0 {
		ownerIDStr = strconv.Itoa(entToken.OwnerID)
	} else {
		// This might indicate an issue if owner is required, but could happen if FK was SET NULL
		log.Printf("WARN: toProtoPlatformTokenInfo - OwnerID not set/found for token ID %d", entToken.ID)
	}

	roleIDStr := ""
	// --- CORRECTED ROLE ID HANDLING ---
	// Get Role ID ONLY from the loaded edge
	if entToken.Edges.Role != nil {
		roleIDStr = strconv.Itoa(entToken.Edges.Role.ID)
	} else {
		// Log if the required edge wasn't loaded - this indicates a problem upstream
		// (e.g., the calling query didn't use WithRole())
		log.Printf("WARN: toProtoPlatformTokenInfo - Role edge not loaded for token ID %d, cannot determine RoleId", entToken.ID)
	}
	// --- END CORRECTION ---

	info := &api.PlatformTokenInfo{
		Id:        strconv.Itoa(entToken.ID),
		PublicId:  entToken.PublicID,
		OwnerId:   ownerIDStr,
		RoleId:    roleIDStr, // Uses the derived roleIDStr
		IsActive:  entToken.IsActive,
		CreatedAt: timestamppb.New(entToken.CreateTime),
		UpdatedAt: timestamppb.New(entToken.UpdateTime),
	}
	if entToken.ExpiresAt != nil && !entToken.ExpiresAt.IsZero() {
		info.ExpiresAt = timestamppb.New(*entToken.ExpiresAt)
	}
	return info
}
