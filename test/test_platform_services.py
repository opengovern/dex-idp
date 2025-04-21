import unittest
import grpc
import uuid
import time # Needed for epoch timestamp in log filename
import logging # Import the logging module
from datetime import datetime, timedelta, timezone

# Assuming your generated files are named api_pb2.py and api_pb2_grpc.py
import api_pb2
import api_pb2_grpc

# Import Protobuf well-known types used in the proto definition
from google.protobuf import timestamp_pb2
from google.protobuf import wrappers_pb2
from google.protobuf import empty_pb2

# Dex gRPC server address (adjust if different)
DEX_GRPC_ADDRESS = '127.0.0.1:5557'
# Dex Client ID to associate roles with (ensure this exists in Dex config)
TEST_APP_ID = "example-app"


# Helper function to create Timestamp protobuf messages
def _get_timestamp(dt=None):
    dt = dt or datetime.now(timezone.utc)
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(dt)
    return ts

class PlatformServiceIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up gRPC channel and stubs once for all tests."""
        # Using insecure channel for local testing without TLS
        cls.channel = grpc.insecure_channel(DEX_GRPC_ADDRESS)
        cls.user_stub = api_pb2_grpc.PlatformUserServiceStub(cls.channel)
        cls.role_stub = api_pb2_grpc.PlatformAppRoleServiceStub(cls.channel)
        cls.token_stub = api_pb2_grpc.PlatformTokenServiceStub(cls.channel)
        cls.identity_stub = api_pb2_grpc.PlatformFederatedIdentityServiceStub(cls.channel)
        # Basic logging configuration (optional, good practice for root logger)
        # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        print(f"Connecting to Dex gRPC at {DEX_GRPC_ADDRESS}...") # Keep console print for initial connection
        try:
             dex_stub = api_pb2_grpc.DexStub(cls.channel)
             dex_stub.GetVersion(api_pb2.VersionReq())
             print("Successfully connected.")
        except grpc.RpcError as e:
             print(f"Failed to connect to Dex gRPC: {e.code()} - {e.details()}")
             raise ConnectionError(f"Could not connect to Dex gRPC at {DEX_GRPC_ADDRESS}")


    @classmethod
    def tearDownClass(cls):
        """Close the channel when tests are done."""
        cls.channel.close()
        print("\nClosed gRPC channel.") # Keep console print for end

    def setUp(self):
        """Set up per-test logging before each test method."""
        test_method_name = self.id().split('.')[-1]
        # Use epoch seconds for unique log filename part
        epoch_id = int(time.time())
        log_filename = f"test-{test_method_name}-{epoch_id}.log"

        self.logger = logging.getLogger(self.id())
        # Ensure logger is clear of previous handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            handler.close()

        self.logger.setLevel(logging.DEBUG)
        self.log_handler = logging.FileHandler(log_filename, mode='w') # Use 'w' to overwrite if somehow reused
        self.log_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        self.logger.addHandler(self.log_handler)

        self.logger.info(f"--- Starting test: {test_method_name} ---")
        # Print to console as well
        print(f"\nRunning Test Scenario: {test_method_name} (Log file: {log_filename})")


    def tearDown(self):
        """Clean up per-test logging after each test method."""
        self.logger.info(f"--- Finished test: {self.id().split('.')[-1]} ---")
        if hasattr(self, 'log_handler') and self.log_handler:
             # Flush handler before closing
             self.log_handler.flush()
             self.logger.removeHandler(self.log_handler)
             self.log_handler.close()
             self.log_handler = None # Clear reference


    # --- Helper Methods for Resource Creation (using logger) ---

    def _create_user(self, email_prefix="testuser", display_name=None, is_active=True):
        user_email = f"{email_prefix}-{uuid.uuid4()}@example.com"
        self.logger.debug(f"Helper: Attempting to create user with email prefix {email_prefix}")
        req = api_pb2.CreatePlatformUserRequest(
            email=user_email,
            display_name=wrappers_pb2.StringValue(value=display_name) if display_name else None,
            is_active=wrappers_pb2.BoolValue(value=is_active)
        )
        try:
            resp = self.user_stub.CreateUser(req)
            self.assertIsNotNone(resp.platform_user)
            self.assertEqual(resp.platform_user.email, user_email)
            self.logger.info(f"Helper: Created User ID: {resp.platform_user.id} (Email: {user_email})")
            return resp.platform_user
        except grpc.RpcError as e:
            self.logger.exception(f"Helper _create_user failed: {e.code()} - {e.details()}", exc_info=True)
            self.fail(f"Helper _create_user failed unexpectedly: {e.code()} - {e.details()}")
        except Exception as e:
             self.logger.exception(f"Helper _create_user failed with non-gRPC error: {e}", exc_info=True)
             self.fail(f"Helper _create_user failed unexpectedly with non-gRPC error: {e}")


    def _create_role(self, title_prefix="TestRole", description=None, is_active=True, app_id=TEST_APP_ID):
        role_title = f"{title_prefix}-{uuid.uuid4()}"
        self.logger.debug(f"Helper: Attempting to create role with title prefix {title_prefix} for app {app_id}")
        req = api_pb2.CreatePlatformAppRoleRequest(
            app_id=app_id,
            title=role_title,
            description=wrappers_pb2.StringValue(value=description) if description else None,
            is_active=wrappers_pb2.BoolValue(value=is_active)
        )
        try:
            resp = self.role_stub.CreatePlatformAppRole(req)
            self.assertIsNotNone(resp.platform_app_role)
            self.assertEqual(resp.platform_app_role.title, role_title)
            self.logger.info(f"Helper: Created Role ID: {resp.platform_app_role.id} (Title: {role_title})")
            return resp.platform_app_role
        except grpc.RpcError as e:
            self.logger.exception(f"Helper _create_role failed: {e.code()} - {e.details()}", exc_info=True)
            self.fail(f"Helper _create_role failed unexpectedly: {e.code()} - {e.details()}")
        except Exception as e:
             self.logger.exception(f"Helper _create_role failed with non-gRPC error: {e}", exc_info=True)
             self.fail(f"Helper _create_role failed unexpectedly with non-gRPC error: {e}")

    def _create_token(self, owner_id, role_id, expires_at=None):
        self.logger.debug(f"Helper: Attempting to create token for owner {owner_id} and role {role_id}")
        req = api_pb2.CreatePlatformTokenRequest(
            owner_id=owner_id,
            role_id=role_id,
            expires_at=expires_at
        )
        try:
            resp = self.token_stub.CreatePlatformToken(req)
            self.assertIsNotNone(resp.platform_token)
            self.assertIsNotNone(resp.secret)
            self.assertTrue(len(resp.secret) > 10)
            self.logger.info(f"Helper: Created Token ID: {resp.platform_token.id} (PublicID: {resp.platform_token.public_id})")
            return resp.platform_token, resp.secret
        except grpc.RpcError as e:
            self.logger.exception(f"Helper _create_token failed: {e.code()} - {e.details()}", exc_info=True)
            self.fail(f"Helper _create_token failed unexpectedly: {e.code()} - {e.details()}")
        except Exception as e:
             self.logger.exception(f"Helper _create_token failed with non-gRPC error: {e}", exc_info=True)
             self.fail(f"Helper _create_token failed unexpectedly with non-gRPC error: {e}")


    # --- Test Case Implementations (Fully Adapted with Logging) ---

    def test_scenario_01_verify_token_after_owner_inactive(self):
        self.logger.info("Setting up Scenario 01...")
        user = self._create_user(is_active=True)
        role = self._create_role(is_active=True)
        token, secret = self._create_token(owner_id=user.id, role_id=role.id)

        self.logger.info("Action: Deactivating owner...")
        update_req = api_pb2.UpdatePlatformUserRequest(id=user.id, is_active=wrappers_pb2.BoolValue(value=False))
        try:
             self.user_stub.UpdateUser(update_req)
             self.logger.info(f"Action: Deactivated User ID: {user.id}")
        except grpc.RpcError as e:
             self.logger.exception(f"Action UpdateUser failed: {e.code()} - {e.details()}", exc_info=True)
             self.fail("UpdateUser failed unexpectedly")

        self.logger.info("Action: Verifying token...")
        verify_req = api_pb2.VerifyPlatformTokenRequest(public_id=token.public_id, secret=secret)
        try:
             verify_resp = self.token_stub.VerifyPlatformToken(verify_req)
             self.logger.info(f"Action: Verification result: verified={verify_resp.verified}")
             self.assertFalse(verify_resp.verified, "Token should NOT be verified after owner made inactive")
             self.logger.info("Outcome: Assertion Passed - Verification correctly failed.")
        except grpc.RpcError as e:
             self.logger.exception(f"Action VerifyPlatformToken failed: {e.code()} - {e.details()}", exc_info=True)
             self.fail("VerifyPlatformToken failed unexpectedly")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting test resources...")
             try:
                  self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
             except grpc.RpcError as e:
                  self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False) # Log cleanup failure as warning
             try:
                  self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
             except grpc.RpcError as e:
                  self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)


    def test_scenario_02_verify_token_after_role_inactive(self):
        self.logger.info("Setting up Scenario 02...")
        user = self._create_user(is_active=True)
        role = self._create_role(is_active=True)
        token, secret = self._create_token(owner_id=user.id, role_id=role.id)

        self.logger.info("Action: Deactivating role...")
        update_req = api_pb2.UpdatePlatformAppRoleRequest(id=role.id, is_active=wrappers_pb2.BoolValue(value=False))
        try:
            self.role_stub.UpdatePlatformAppRole(update_req)
            self.logger.info(f"Action: Deactivated Role ID: {role.id}")
        except grpc.RpcError as e:
            self.logger.exception(f"Action UpdatePlatformAppRole failed: {e.code()} - {e.details()}", exc_info=True)
            self.fail("UpdatePlatformAppRole failed unexpectedly")

        self.logger.info("Action: Verifying token...")
        verify_req = api_pb2.VerifyPlatformTokenRequest(public_id=token.public_id, secret=secret)
        try:
            verify_resp = self.token_stub.VerifyPlatformToken(verify_req)
            self.logger.info(f"Action: Verification result: verified={verify_resp.verified}")
            self.assertFalse(verify_resp.verified, "Token should NOT be verified after role made inactive")
            self.logger.info("Outcome: Assertion Passed - Verification correctly failed.")
        except grpc.RpcError as e:
            self.logger.exception(f"Action VerifyPlatformToken failed: {e.code()} - {e.details()}", exc_info=True)
            self.fail("VerifyPlatformToken failed unexpectedly")
        finally:
            # Cleanup
            self.logger.info("Cleanup: Deleting test resources...")
            try:
                 self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
            except grpc.RpcError as e:
                 self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
            try:
                 self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
            except grpc.RpcError as e:
                 self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)


    def test_scenario_03_verify_token_after_expiry(self):
        self.logger.info("Setting up Scenario 03...")
        user = self._create_user(is_active=True)
        role = self._create_role(is_active=True)
        past_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        expires_ts = _get_timestamp(past_time)
        token, secret = self._create_token(owner_id=user.id, role_id=role.id, expires_at=expires_ts)
        self.logger.info(f"Setup: Created token with expiry: {past_time}")

        self.logger.info("Action: Verifying token...")
        verify_req = api_pb2.VerifyPlatformTokenRequest(public_id=token.public_id, secret=secret)
        try:
            verify_resp = self.token_stub.VerifyPlatformToken(verify_req)
            self.logger.info(f"Action: Verification result: verified={verify_resp.verified}")
            self.assertFalse(verify_resp.verified, "Token should NOT be verified after expiry time")
            self.logger.info("Outcome: Assertion Passed - Verification correctly failed.")
        except grpc.RpcError as e:
             self.logger.exception(f"Action VerifyPlatformToken failed: {e.code()} - {e.details()}", exc_info=True)
             self.fail("VerifyPlatformToken failed unexpectedly")
        finally:
            # Cleanup
            self.logger.info("Cleanup: Deleting test resources...")
            try:
                 self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
            except grpc.RpcError as e:
                 self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
            try:
                 self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
            except grpc.RpcError as e:
                 self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)


    def test_scenario_04_note_public_id_reuse_check(self):
         self.logger.info("Skipping Test Scenario 04: Public ID Prefix Reuse (requires specific server logic knowledge)")
         self.skipTest("Requires knowledge of specific public_id generation logic")


    def test_scenario_05_assign_non_existent_role_to_user(self):
        self.logger.info("Setting up Scenario 05...")
        user = None
        try:
             user = self._create_user()
             non_existent_role_id = f"role-{uuid.uuid4()}"
             self.logger.info(f"Setup: Using non-existent Role ID: {non_existent_role_id}")

             req = api_pb2.AssignRoleToUserRequest(platform_user_id=user.id, platform_app_role_id=non_existent_role_id)
             self.logger.info("Action: Attempting to assign non-existent role...")
             with self.assertRaises(grpc.RpcError) as cm:
                 self.user_stub.AssignRoleToUser(req)

             # Log the specific error code received
             self.logger.info(f"Action: Received expected failure: {cm.exception.code()}")
             self.assertIn(cm.exception.code(), [grpc.StatusCode.NOT_FOUND, grpc.StatusCode.INVALID_ARGUMENT],
                           f"Assigning non-existent role should fail with NotFound or InvalidArgument, not {cm.exception.code()}")
             self.logger.info("Outcome: Assertion Passed - RPC correctly failed.")
        except Exception as e: # Catch unexpected exceptions during setup or test
             self.logger.exception("Unexpected exception during test_scenario_05", exc_info=True)
             self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             if user:
                  self.logger.info("Cleanup: Deleting test resources...")
                  try:
                       self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
                  except grpc.RpcError as e:
                       self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)


    def test_scenario_06_delete_role_assigned_to_token(self):
        self.logger.info("Setting up Scenario 06...")
        user = None
        role = None
        token = None
        secret = None
        try:
            user = self._create_user()
            role = self._create_role()
            token, secret = self._create_token(owner_id=user.id, role_id=role.id)
            self.logger.info(f"Setup: Token {token.id} uses Role {role.id}")

            self.logger.info("Action: Deleting Role...")
            # Assumption: Server allows deleting roles even if assigned, but tokens become invalid.
            self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
            self.logger.info(f"Action: Role delete call succeeded for Role ID: {role.id}")
            role_id_deleted = role.id # Store ID for cleanup checks
            role = None # Mark role as deleted

            self.logger.info("Check 1: Verifying Token after role delete...")
            verify_req = api_pb2.VerifyPlatformTokenRequest(public_id=token.public_id, secret=secret)
            verify_resp = self.token_stub.VerifyPlatformToken(verify_req)
            self.assertFalse(verify_resp.verified, "Token verification should fail after its role is deleted")
            self.logger.info("Outcome 1: Assertion Passed - Verification correctly failed.")

            self.logger.info("Check 2: Getting Token after role delete...")
            # Assumption: Get succeeds but role is invalid/missing, or Get fails.
            try:
                get_req = api_pb2.GetPlatformTokenRequest(id=token.id)
                get_resp = self.token_stub.GetPlatformToken(get_req)
                self.logger.info(f"Check 2: Get Token {token.id} succeeded.")
                # Depending on implementation, check if role is missing or invalid
                # self.assertFalse(get_resp.platform_token.HasField("role"), "Role field should be missing")
            except grpc.RpcError as e:
                self.logger.info(f"Check 2: Get Token {token.id} failed as expected (Code: {e.code()})")
                self.assertIn(e.code(), [grpc.StatusCode.NOT_FOUND, grpc.StatusCode.FAILED_PRECONDITION],
                              f"If Get Token fails after role delete, code should be NotFound or FailedPrecondition, not {e.code()}")
            self.logger.info("Outcome 2: Checked Get Token behavior after role delete.")

        except Exception as e:
            self.logger.exception("Unexpected exception during test_scenario_06", exc_info=True)
            self.fail(f"Test failed unexpectedly: {e}")
        finally:
            # Cleanup
            self.logger.info("Cleanup: Deleting test resources...")
            if user:
                try:
                    self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
                except grpc.RpcError as e:
                     self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
            if role: # If deletion failed above
                try:
                    self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
                except grpc.RpcError as e:
                     self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)
            elif 'role_id_deleted' in locals(): # If deleted successfully in test
                 # Verify role is actually gone
                 try:
                      self.role_stub.GetPlatformAppRole(api_pb2.GetPlatformAppRoleRequest(id=role_id_deleted))
                      self.logger.error(f"Cleanup check failed: Role {role_id_deleted} still exists after delete.")
                 except grpc.RpcError as e:
                      self.assertEqual(e.code(), grpc.StatusCode.NOT_FOUND, f"Role {role_id_deleted} should be NotFound after delete")
                      self.logger.info(f"Cleanup check passed: Role {role_id_deleted} is deleted.")
            if token: # If Get check succeeded, token might still exist
                 try:
                      self.token_stub.DeletePlatformToken(api_pb2.DeletePlatformTokenRequest(id=token.id))
                 except grpc.RpcError as e:
                      # Might be already deleted by user cascade
                      self.assertEqual(e.code(), grpc.StatusCode.NOT_FOUND, "Token delete should fail with NotFound if already gone")


    def test_scenario_07_update_token_role_to_non_existent(self):
        self.logger.info("Setting up Scenario 07...")
        user = None
        role = None
        token = None
        try:
            user = self._create_user()
            role = self._create_role()
            token, _ = self._create_token(owner_id=user.id, role_id=role.id)
            non_existent_role_id = f"role-{uuid.uuid4()}"
            self.logger.info(f"Setup: Using non-existent Role ID: {non_existent_role_id}")

            req = api_pb2.UpdatePlatformTokenRequest(id=token.id, new_role_id=non_existent_role_id)
            self.logger.info(f"Action: Attempting to update token {token.id} to non-existent role...")
            with self.assertRaises(grpc.RpcError) as cm:
                self.token_stub.UpdatePlatformToken(req)

            self.logger.info(f"Action: Received expected failure: {cm.exception.code()}")
            self.assertIn(cm.exception.code(), [grpc.StatusCode.NOT_FOUND, grpc.StatusCode.INVALID_ARGUMENT],
                           f"Updating token to non-existent role should fail with NotFound/InvalidArgument, not {cm.exception.code()}")
            self.logger.info("Outcome: Assertion Passed - RPC correctly failed.")

            self.logger.info("Check: Verifying token role remains unchanged...")
            get_resp = self.token_stub.GetPlatformToken(api_pb2.GetPlatformTokenRequest(id=token.id))
            self.assertEqual(get_resp.platform_token.role.id, role.id, "Token's role should remain unchanged after failed update")
            self.logger.info("Check: Token role confirmed unchanged.")

        except Exception as e:
            self.logger.exception("Unexpected exception during test_scenario_07", exc_info=True)
            self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting test resources...")
             if user:
                  try:
                      self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
                  except grpc.RpcError as e:
                      self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
             if role:
                  try:
                      self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
                  except grpc.RpcError as e:
                      self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)


    def test_scenario_08_role_title_uniqueness_violation(self):
        self.logger.info("Setting up Scenario 08...")
        role1 = None
        # Use a unique app_id to prevent collisions across test runs if cleanup fails
        app_id_for_test = f"app-{uuid.uuid4()}"
        try:
            role1_title = "UniqueAdminRoleForTest08" # Use fixed title for test predictability
            role1 = self._create_role(title_prefix=role1_title, app_id=app_id_for_test)
            self.logger.info(f"Setup: Created Role {role1.id} with title '{role1.title}' for app '{app_id_for_test}'")

            req = api_pb2.CreatePlatformAppRoleRequest(app_id=app_id_for_test, title=role1.title)
            self.logger.info(f"Action: Attempting to create another role with title '{role1.title}' for app '{app_id_for_test}'...")
            with self.assertRaises(grpc.RpcError) as cm:
                self.role_stub.CreatePlatformAppRole(req)

            self.logger.info(f"Action: Received expected failure: {cm.exception.code()}")
            self.assertIn(cm.exception.code(), [grpc.StatusCode.ALREADY_EXISTS, grpc.StatusCode.INVALID_ARGUMENT],
                          f"Creating role with duplicate title/app_id should fail with AlreadyExists/InvalidArgument, not {cm.exception.code()}")
            self.logger.info("Outcome: Assertion Passed - RPC correctly failed.")

        except Exception as e:
             self.logger.exception("Unexpected exception during test_scenario_08", exc_info=True)
             self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting test resources...")
             if role1:
                  try:
                      self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role1.id))
                  except grpc.RpcError as e:
                      self.logger.warning(f"Cleanup failed for role {role1.id}: {e.code()}", exc_info=False)


    def test_scenario_09_delete_user_owning_token(self):
        self.logger.info("Setting up Scenario 09...")
        # Assumption: Server cascades delete from User to Token
        user = None
        role = None
        token = None
        try:
            user = self._create_user()
            role = self._create_role()
            token, _ = self._create_token(owner_id=user.id, role_id=role.id)
            self.logger.info(f"Setup: User {user.id} owns Token {token.id}")
            token_id_deleted = token.id # Store for check

            self.logger.info(f"Action: Deleting User ID: {user.id}")
            self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
            self.logger.info("Action: User delete call succeeded.")
            user_id_deleted = user.id # Store for check
            user = None # Mark as deleted

            self.logger.info(f"Check: Attempting to Get Token ID: {token_id_deleted} after owner delete")
            with self.assertRaises(grpc.RpcError) as cm:
                 self.token_stub.GetPlatformToken(api_pb2.GetPlatformTokenRequest(id=token_id_deleted))

            self.logger.info(f"Check: Received expected failure: {cm.exception.code()}")
            self.assertEqual(cm.exception.code(), grpc.StatusCode.NOT_FOUND,
                             f"Getting token after owner deleted should fail with NotFound, not {cm.exception.code()}")
            self.logger.info("Outcome: Assertion Passed - Get token correctly failed with NotFound.")

        except Exception as e:
            self.logger.exception("Unexpected exception during test_scenario_09", exc_info=True)
            self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting remaining resources...")
             if user: # If delete failed above
                  try:
                      self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
                  except grpc.RpcError as e:
                      self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
             elif 'user_id_deleted' in locals(): # If deleted in test
                  # Verify user is actually gone
                  try:
                       self.user_stub.GetUser(api_pb2.GetPlatformUserRequest(id=user_id_deleted))
                       self.logger.error(f"Cleanup check failed: User {user_id_deleted} still exists.")
                  except grpc.RpcError as e:
                       self.assertEqual(e.code(), grpc.StatusCode.NOT_FOUND, f"User {user_id_deleted} should be NotFound")
                       self.logger.info(f"Cleanup check passed: User {user_id_deleted} is deleted.")
             if role:
                  try:
                      self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
                  except grpc.RpcError as e:
                      self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)


    def test_scenario_10_list_user_assignments_with_filtering(self):
        self.logger.info("Setting up Scenario 10...")
        user = None
        role1, role2, role3 = None, None, None
        try:
            user = self._create_user()
            app1 = f"app-{uuid.uuid4()}"
            app2 = f"app-{uuid.uuid4()}"
            role1 = self._create_role(title_prefix="RoleA1", app_id=app1, is_active=True)
            role2 = self._create_role(title_prefix="RoleA2", app_id=app1, is_active=False)
            role3 = self._create_role(title_prefix="RoleB1", app_id=app2, is_active=True)
            self.user_stub.AssignRoleToUser(api_pb2.AssignRoleToUserRequest(platform_user_id=user.id, platform_app_role_id=role1.id))
            self.user_stub.AssignRoleToUser(api_pb2.AssignRoleToUserRequest(platform_user_id=user.id, platform_app_role_id=role2.id))
            self.user_stub.AssignRoleToUser(api_pb2.AssignRoleToUserRequest(platform_user_id=user.id, platform_app_role_id=role3.id))
            self.logger.info(f"Setup: Assigned Roles {role1.id}, {role2.id}, {role3.id} to User {user.id}")

            # Action 1: Filter by app_id
            req1 = api_pb2.ListUserAssignmentsRequest(platform_user_id=user.id, filter_app_id=app1)
            self.logger.info(f"Action 1: Listing assignments for User {user.id} filtering by app_id={app1}")
            resp1 = self.user_stub.ListUserAssignments(req1)
            returned_role_ids1 = {r.id for r in resp1.assigned_roles}
            self.logger.info(f"Outcome 1: Received {len(returned_role_ids1)} roles: {returned_role_ids1}")
            self.assertEqual(len(resp1.assigned_roles), 2, "Should find 2 roles for app1")
            self.assertIn(role1.id, returned_role_ids1)
            self.assertIn(role2.id, returned_role_ids1)
            self.logger.info("Outcome 1: Assertion Passed - Correct roles returned.")

            # Action 2: Filter by app_id and active role status
            req2 = api_pb2.ListUserAssignmentsRequest(
                platform_user_id=user.id,
                filter_app_id=app1,
                filter_role_is_active=wrappers_pb2.BoolValue(value=True)
            )
            self.logger.info(f"Action 2: Listing assignments for User {user.id} filtering by app_id={app1} and active roles")
            resp2 = self.user_stub.ListUserAssignments(req2)
            returned_role_ids2 = {r.id for r in resp2.assigned_roles}
            self.logger.info(f"Outcome 2: Received {len(returned_role_ids2)} roles: {returned_role_ids2}")
            self.assertEqual(len(resp2.assigned_roles), 1, "Should find 1 active role for app1")
            self.assertEqual(resp2.assigned_roles[0].id, role1.id, "Should be the active role (role1)")
            self.logger.info("Outcome 2: Assertion Passed - Correct active role returned.")

        except Exception as e:
            self.logger.exception("Unexpected exception during test_scenario_10", exc_info=True)
            self.fail(f"Test failed unexpectedly: {e}")
        finally:
            # Cleanup
            self.logger.info("Cleanup: Deleting test resources...")
            # Role assignments deleted by user delete cascade assumed
            if user:
                 try:
                      self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
                 except grpc.RpcError as e:
                      self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
            # Delete roles individually
            for role_obj in [role1, role2, role3]:
                 if role_obj:
                      try:
                           self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role_obj.id))
                      except grpc.RpcError as e:
                           self.logger.warning(f"Cleanup failed for role {role_obj.id}: {e.code()}", exc_info=False)


    def test_scenario_11_note_skip_federated_identity_assignment(self):
        self.logger.info("Skipping Test Scenario 11: Federated Identity vs User Role Assignment (requires federated identity setup)")
        self.skipTest("Requires federated identity setup or API mocking")


    def test_scenario_12_token_creation_with_non_existent_user(self):
        self.logger.info("Setting up Scenario 12...")
        role = None
        try:
            role = self._create_role()
            non_existent_user_id = f"user-{uuid.uuid4()}"
            self.logger.info(f"Setup: Using non-existent User ID: {non_existent_user_id}")

            req = api_pb2.CreatePlatformTokenRequest(owner_id=non_existent_user_id, role_id=role.id)
            self.logger.info("Action: Attempting to create token with non-existent owner...")
            with self.assertRaises(grpc.RpcError) as cm:
                self.token_stub.CreatePlatformToken(req)

            self.logger.info(f"Action: Received expected failure: {cm.exception.code()}")
            self.assertIn(cm.exception.code(), [grpc.StatusCode.NOT_FOUND, grpc.StatusCode.INVALID_ARGUMENT],
                          f"Creating token with non-existent user should fail with NotFound/InvalidArgument, not {cm.exception.code()}")
            self.logger.info("Outcome: Assertion Passed - RPC correctly failed.")

        except Exception as e:
            self.logger.exception("Unexpected exception during test_scenario_12", exc_info=True)
            self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting test resources...")
             if role:
                  try:
                      self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
                  except grpc.RpcError as e:
                      self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)


    def test_scenario_13_update_role_title_and_verify_token_get(self):
        self.logger.info("Setting up Scenario 13...")
        user = None
        role = None
        token = None
        try:
            user = self._create_user()
            role = self._create_role(title_prefix="OldTitle")
            token, _ = self._create_token(owner_id=user.id, role_id=role.id)
            new_title = f"NewTitle-{uuid.uuid4()}"

            self.logger.info("Action 1: Updating role title...")
            update_req = api_pb2.UpdatePlatformAppRoleRequest(id=role.id, title=wrappers_pb2.StringValue(value=new_title))
            self.role_stub.UpdatePlatformAppRole(update_req)
            self.logger.info(f"Action 1: Updated role {role.id} title to '{new_title}'")

            self.logger.info(f"Action 2: Getting Token {token.id}...")
            get_req = api_pb2.GetPlatformTokenRequest(id=token.id)
            get_resp = self.token_stub.GetPlatformToken(get_req)
            self.logger.info("Action 2: Get Token succeeded.")

            self.assertIsNotNone(get_resp.platform_token.role, "Token response should include nested role info")
            self.assertEqual(get_resp.platform_token.role.title, new_title, "Nested role in Get token should have the updated title")
            self.logger.info("Outcome: Assertion Passed - Get token correctly shows updated role title.")

        except Exception as e:
            self.logger.exception("Unexpected exception during test_scenario_13", exc_info=True)
            self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting test resources...")
             if user:
                  try:
                       self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
                  except grpc.RpcError as e:
                       self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
             if role:
                  try:
                       self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
                  except grpc.RpcError as e:
                       self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)


    def test_scenario_14_pagination_exhaustion(self):
        self.logger.info("Setting up Scenario 14...")
        created_user_ids = set()
        try:
            page_size = 3
            num_users = page_size + 2 # e.g., 5 users
            for i in range(num_users):
                 user = self._create_user(email_prefix=f"pageuser{i}")
                 created_user_ids.add(user.id)
            self.logger.info(f"Setup: Created {num_users} users.")

            retrieved_user_ids = set()
            next_page_tok = None
            page_num = 0
            max_pages = (num_users // page_size) + 3 # Safety limit
            while page_num < max_pages:
                page_num += 1
                self.logger.info(f"Action: Listing page {page_num} (token: {next_page_tok})...")
                req = api_pb2.ListPlatformUsersRequest(page_size=page_size, page_token=next_page_tok or "")
                resp = self.user_stub.ListUsers(req)

                page_user_ids = {u.id for u in resp.users}
                self.logger.info(f"Action: Received {len(page_user_ids)} users this page.")
                self.assertTrue(len(page_user_ids) <= page_size, f"Page {page_num} returned more users than page size")

                # Check for duplicates across pages
                duplicate_ids = retrieved_user_ids.intersection(page_user_ids)
                self.assertFalse(duplicate_ids, f"Duplicate users found in pagination: {duplicate_ids}")
                retrieved_user_ids.update(page_user_ids)

                next_page_tok = resp.next_page_token
                if not next_page_tok:
                    self.logger.info("Action: Reached end of pagination.")
                    break
            else:
                 # This else block executes if the while loop completes without break (hit max_pages)
                 self.fail(f"Pagination did not complete within {max_pages} requests.")


            self.assertEqual(retrieved_user_ids, created_user_ids, "Pagination should retrieve all created users exactly once")
            self.logger.info("Outcome: Assertion Passed - Pagination correctly retrieved all users.")

        except Exception as e:
             self.logger.exception("Unexpected exception during test_scenario_14", exc_info=True)
             self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting test resources...")
             for user_id in created_user_ids:
                  try:
                       self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user_id))
                  except grpc.RpcError as e:
                       self.logger.warning(f"Cleanup failed for user {user_id}: {e.code()}", exc_info=False)


    def test_scenario_15_filter_expired_tokens_list(self):
        self.logger.info("Setting up Scenario 15...")
        user = None
        role = None
        token_active, token_expired, token_no_expiry = None, None, None
        try:
            user = self._create_user()
            role = self._create_role()
            now = datetime.now(timezone.utc)
            expires_future_ts = _get_timestamp(now + timedelta(hours=1))
            expires_past_ts = _get_timestamp(now - timedelta(hours=1))

            token_active, _ = self._create_token(owner_id=user.id, role_id=role.id, expires_at=expires_future_ts)
            token_expired, _ = self._create_token(owner_id=user.id, role_id=role.id, expires_at=expires_past_ts)
            token_no_expiry, _ = self._create_token(owner_id=user.id, role_id=role.id, expires_at=None)
            self.logger.info(f"Setup: Created active token {token_active.id}, expired token {token_expired.id}, no-expiry token {token_no_expiry.id}")

            req = api_pb2.ListPlatformTokensRequest(
                filter_owner_id=user.id, # Filter for the user to avoid other test tokens
                filter_exclude_expired=wrappers_pb2.BoolValue(value=True)
            )
            self.logger.info("Action: Listing tokens with filter_exclude_expired=true...")
            resp = self.token_stub.ListPlatformTokens(req)

            returned_token_ids = {t.id for t in resp.tokens}
            self.logger.info(f"Outcome: Received {len(returned_token_ids)} tokens: {returned_token_ids}")

            self.assertIn(token_active.id, returned_token_ids, "Active token should be returned")
            self.assertIn(token_no_expiry.id, returned_token_ids, "Token with no expiry should be returned")
            self.assertNotIn(token_expired.id, returned_token_ids, "Expired token should NOT be returned")
            # Assuming token with no expiry is considered non-expired
            self.assertEqual(len(returned_token_ids), 2, "Should only return the active and non-expiring tokens")
            self.logger.info("Outcome: Assertion Passed - Correctly filtered expired token.")

        except Exception as e:
            self.logger.exception("Unexpected exception during test_scenario_15", exc_info=True)
            self.fail(f"Test failed unexpectedly: {e}")
        finally:
             # Cleanup
             self.logger.info("Cleanup: Deleting test resources...")
             if user:
                  try:
                       self.user_stub.DeleteUser(api_pb2.DeletePlatformUserRequest(id=user.id))
                  except grpc.RpcError as e:
                       self.logger.warning(f"Cleanup failed for user {user.id}: {e.code()}", exc_info=False)
             if role:
                  try:
                       self.role_stub.DeletePlatformAppRole(api_pb2.DeletePlatformAppRoleRequest(id=role.id))
                  except grpc.RpcError as e:
                       self.logger.warning(f"Cleanup failed for role {role.id}: {e.code()}", exc_info=False)
             # Tokens assumed deleted by user cascade


if __name__ == '__main__':
    # unittest.main() will run all methods starting with 'test'
    print("Starting Dex Platform Service Integration Tests with per-test logging...")
    unittest.main(verbosity=1) # verbosity=1 is default, 2 prints test names too