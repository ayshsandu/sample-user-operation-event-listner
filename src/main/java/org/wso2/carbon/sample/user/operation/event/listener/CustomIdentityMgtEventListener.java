package org.wso2.carbon.sample.user.operation.event.listener;

import org.apache.axis2.context.MessageContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.mgt.IdentityMgtConfig;
import org.wso2.carbon.identity.mgt.IdentityMgtEventListener;
import org.wso2.carbon.identity.mgt.NotificationSender;
import org.wso2.carbon.identity.mgt.NotificationSendingModule;
import org.wso2.carbon.identity.mgt.config.Config;
import org.wso2.carbon.identity.mgt.config.ConfigBuilder;
import org.wso2.carbon.identity.mgt.config.ConfigType;
import org.wso2.carbon.identity.mgt.config.StorageType;
import org.wso2.carbon.identity.mgt.dto.NotificationDataDTO;
import org.wso2.carbon.identity.mgt.dto.UserIdentityClaimsDO;
import org.wso2.carbon.identity.mgt.mail.Notification;
import org.wso2.carbon.identity.mgt.mail.NotificationBuilder;
import org.wso2.carbon.identity.mgt.mail.NotificationData;
import org.wso2.carbon.identity.mgt.policy.PolicyRegistry;
import org.wso2.carbon.identity.mgt.store.UserIdentityDataStore;
import org.wso2.carbon.identity.mgt.util.UserIdentityManagementUtil;
import org.wso2.carbon.identity.mgt.util.Utils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class CustomIdentityMgtEventListener extends IdentityMgtEventListener {

    private static final Log log = LogFactory.getLog(CustomIdentityMgtEventListener.class);
    private static final String EMAIL_NOTIFICATION_TYPE = "EMAIL";
    PolicyRegistry policyRegistry = null;
    private UserIdentityDataStore module;
    private IdentityMgtConfig identityMgtConfig;
    // Set of thread local variable names
    private static final String DO_PRE_AUTHENTICATE = "doPreAuthenticate";
    private static final String DO_POST_AUTHENTICATE = "doPostAuthenticate";

    public CustomIdentityMgtEventListener() {
        super();
        identityMgtConfig = IdentityMgtConfig.getInstance();
        // Get the policy registry with the loaded policies.
        policyRegistry = identityMgtConfig.getPolicyRegistry();
        module = IdentityMgtConfig.getInstance().getIdentityDataStore();
    }

    @Override
    public boolean doPreAuthenticate(String userName, Object credential, UserStoreManager userStoreManager) throws UserStoreException {
        if (!isEnable()) {
            return true;
        }

        // Top level try and finally blocks are used to unset thread local variables
        try {
            if (!IdentityUtil.threadLocalProperties.get().containsKey(DO_PRE_AUTHENTICATE)) {
                IdentityUtil.threadLocalProperties.get().put(DO_PRE_AUTHENTICATE, true);

                if (log.isDebugEnabled()) {
                    log.debug("Pre authenticator is called in IdentityMgtEventListener");
                }

                IdentityUtil.clearIdentityErrorMsg();

                CustomIdentityMgtConfig config = CustomIdentityMgtConfig.getInstance();

                if (!config.isEnableAuthPolicy()) {
                    return true;
                }

                String domainName = userStoreManager.getRealmConfiguration().getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                String usernameWithDomain = UserCoreUtil.addDomainToName(userName, domainName);
                boolean isUserExistInCurrentDomain = userStoreManager.isExistingUser(usernameWithDomain);

                if (!isUserExistInCurrentDomain) {

                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);

                    if (log.isDebugEnabled()) {
                        log.debug("Username :" + userName + "does not exists in the system, ErrorCode :" + UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
                    }
                    if (config.isAuthPolicyAccountExistCheck()) {
                        throw new UserStoreException(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
                    }
                } else {

                    UserIdentityClaimsDO userIdentityDTO = module.load(userName, userStoreManager);

                    // if the account is locked, should not be able to log in
                    if (userIdentityDTO != null && userIdentityDTO.isAccountLocked()) {

                        // If unlock time is specified then unlock the account.
                        if ((userIdentityDTO.getUnlockTime() != 0) && (System.currentTimeMillis() >= userIdentityDTO.getUnlockTime())) {

                            userIdentityDTO.setAccountLock(false);
                            userIdentityDTO.setUnlockTime(0);

                            try {
                                module.store(userIdentityDTO, userStoreManager);
                            } catch (IdentityException e) {
                                throw new UserStoreException(
                                        "Error while saving user store data for user : "
                                                + userName, e);
                            }
                        } else {
                            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                                    UserCoreConstants.ErrorCode.USER_IS_LOCKED,
                                    userIdentityDTO.getFailAttempts(),
                                    config.getAuthPolicyMaxLoginAttempts(domainName));
                            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                            String errorMsg = "User account is locked for user : " + userName
                                    + ". cannot login until the account is unlocked ";
                            log.warn(errorMsg);
                            throw new UserStoreException(UserCoreConstants.ErrorCode.USER_IS_LOCKED + " "
                                    + errorMsg);
                        }
                    }
                }
            }
            return true;

        } finally {
            // remove thread local variable
            IdentityUtil.threadLocalProperties.get().remove(DO_PRE_AUTHENTICATE);
        }
    }

    /**
     * This method locks the accounts after a configured number of
     * authentication failure attempts. And unlocks accounts based on successful
     * authentications.
     */
    @Override
    public boolean doPostAuthenticate(String userName, boolean authenticated,
                                      UserStoreManager userStoreManager) throws UserStoreException {
        if (!isEnable()) {
            return true;
        }

        // Top level try and finally blocks are used to unset thread local variables
        try {
            if (!IdentityUtil.threadLocalProperties.get().containsKey(DO_POST_AUTHENTICATE)) {
                IdentityUtil.threadLocalProperties.get().put(DO_POST_AUTHENTICATE, true);

                if (log.isDebugEnabled()) {
                    log.debug("Post authenticator is called in IdentityMgtEventListener");
                }

                CustomIdentityMgtConfig config = CustomIdentityMgtConfig.getInstance();

                if (!config.isEnableAuthPolicy()) {
                    return true;
                }

                UserIdentityClaimsDO userIdentityDTO = module.load(userName, userStoreManager);
                if (userIdentityDTO == null) {
                    userIdentityDTO = new UserIdentityClaimsDO(userName);
                }

                boolean userOTPEnabled = userIdentityDTO.getOneTimeLogin();

                // One time password check
                if (authenticated && config.isAuthPolicyOneTimePasswordCheck() &&
                        (!userStoreManager.isReadOnly()) && userOTPEnabled) {

                    // reset password of the user and notify user of the new password

                    String password = new String(UserIdentityManagementUtil.generateTemporaryPassword());
                    userStoreManager.updateCredentialByAdmin(userName, password);

                    // Get email user claim value
                    String email = userStoreManager.getUserClaimValue(userName, UserCoreConstants.ClaimTypeURIs.EMAIL_ADDRESS,
                            null);

                    if (StringUtils.isBlank(email)) {
                        throw new UserStoreException("No user email provided for user : " + userName);
                    }

                    List<NotificationSendingModule> notificationModules =
                            config.getNotificationSendingModules();

                    if (notificationModules != null) {

                        NotificationDataDTO notificationData = new NotificationDataDTO();
                        if (MessageContext.getCurrentMessageContext() != null &&
                                MessageContext.getCurrentMessageContext().getProperty(
                                        MessageContext.TRANSPORT_HEADERS) != null) {
                            notificationData.setTransportHeaders(new HashMap(
                                    (Map) MessageContext.getCurrentMessageContext().getProperty(
                                            MessageContext.TRANSPORT_HEADERS)));
                        }

                        NotificationData emailNotificationData = new NotificationData();
                        String emailTemplate = null;
                        int tenantId = userStoreManager.getTenantId();
                        String firstName = null;
                        try {
                            firstName =
                                    Utils.getClaimFromUserStoreManager(userName, tenantId,
                                            "http://wso2.org/claims/givenname");
                        } catch (IdentityException e2) {
                            throw new UserStoreException("Could not load user given name", e2);
                        }
                        emailNotificationData.setTagData("first-name", firstName);
                        emailNotificationData.setTagData("user-name", userName);
                        emailNotificationData.setTagData("otp-password", password);

                        emailNotificationData.setSendTo(email);

                        Config emailConfig = null;
                        ConfigBuilder configBuilder = ConfigBuilder.getInstance();
                        try {
                            emailConfig =
                                    configBuilder.loadConfiguration(ConfigType.EMAIL,
                                            StorageType.REGISTRY,
                                            tenantId);
                        } catch (Exception e1) {
                            throw new UserStoreException(
                                    "Could not load the email template configuration for user : "
                                            + userName, e1);
                        }

                        emailTemplate = emailConfig.getProperty("otp");

                        Notification emailNotification = null;
                        try {
                            emailNotification =
                                    NotificationBuilder.createNotification(EMAIL_NOTIFICATION_TYPE, emailTemplate,
                                            emailNotificationData);
                        } catch (Exception e) {
                            throw new UserStoreException(
                                    "Could not create the email notification for template: "
                                            + emailTemplate, e);
                        }
                        NotificationSender sender = new NotificationSender();

                        for (NotificationSendingModule notificationSendingModule : notificationModules) {

                            if (IdentityMgtConfig.getInstance().isNotificationInternallyManaged()) {
                                notificationSendingModule.setNotificationData(notificationData);
                                notificationSendingModule.setNotification(emailNotification);
                                sender.sendNotification(notificationSendingModule);
                                notificationData.setNotificationSent(true);
                            }
                        }

                    } else {
                        throw new UserStoreException("No notification modules configured");
                    }


                }

                // Password expire check. Not for OTP enabled users.
                if (authenticated && config.isAuthPolicyExpirePasswordCheck() && !userOTPEnabled && (!userStoreManager.isReadOnly())) {
                    // TODO - password expire impl
                    // Refactor adduser and change password api to stamp the time
                    // Check user's expire time in the claim
                    // if expired redirect to change password
                    // else pass through
                }


                if (!authenticated && config.isAuthPolicyAccountLockOnFailure()) {
                    // reading the max allowed #of failure attempts

                    String domainName = userStoreManager.getRealmConfiguration().getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                    String usernameWithDomain = UserCoreUtil.addDomainToName(userName, domainName);
                    boolean isUserExistInCurrentDomain = userStoreManager.isExistingUser(usernameWithDomain);

                    if (isUserExistInCurrentDomain) {
                        userIdentityDTO.setFailAttempts();

                        if (userIdentityDTO.getFailAttempts() >= config.getAuthPolicyMaxLoginAttempts(domainName)) {
                            log.info("User, " + userName + " has exceed the max failed login attempts. " +
                                    "User account would be locked");
                            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.USER_IS_LOCKED,
                                    userIdentityDTO.getFailAttempts(), config.getAuthPolicyMaxLoginAttempts(domainName));
                            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);

                            if (log.isDebugEnabled()) {
                                log.debug("Username :" + userName + "Exceeded the maximum login attempts. User locked, ErrorCode :" + UserCoreConstants.ErrorCode.USER_IS_LOCKED);
                            }

                            userIdentityDTO.setAccountLock(true);
                            userIdentityDTO.setFailAttempts(0);
                            // lock time from the config
                            int lockTime = config.getAuthPolicyLockingTime(domainName);
                            if (lockTime != 0) {
                                userIdentityDTO.setUnlockTime(System.currentTimeMillis() +
                                        (lockTime * 60 * 1000L));
                            }
                        } else {
                            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL,
                                    userIdentityDTO.getFailAttempts(), config.getAuthPolicyMaxLoginAttempts(domainName));
                            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);

                            if (log.isDebugEnabled()) {
                                log.debug("Username :" + userName + "Invalid Credential, ErrorCode :" + UserCoreConstants.ErrorCode.INVALID_CREDENTIAL);
                            }

                        }

                        try {
                            module.store(userIdentityDTO, userStoreManager);
                        } catch (IdentityException e) {
                            throw new UserStoreException("Error while saving user store data for user : "
                                    + userName, e);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("User, " + userName + " is not exists in " + domainName);
                        }
                    }

                } else {
                    // if the account was locked due to account verification process,
                    // the unlock the account and reset the number of failedAttempts
                    if (userIdentityDTO.isAccountLocked() || userIdentityDTO.getFailAttempts() > 0 || userIdentityDTO.getAccountLock()) {
                        userIdentityDTO.setAccountLock(false);
                        userIdentityDTO.setFailAttempts(0);
                        userIdentityDTO.setUnlockTime(0);
                        try {
                            module.store(userIdentityDTO, userStoreManager);
                        } catch (IdentityException e) {
                            throw new UserStoreException("Error while saving user store data for user : "
                                    + userName, e);
                        }
                    }
                }
            }
            return true;
        } finally {
            // Remove thread local variable
            IdentityUtil.threadLocalProperties.get().remove(DO_POST_AUTHENTICATE);
        }
    }


    @Override
    public boolean doPostAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profile, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPostAddUser(userName, credential, roleList, claims, profile, userStoreManager);
    }

    @Override
    public boolean doPreAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profile, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPreAddUser(userName, credential, roleList, claims, profile, userStoreManager);
    }

    @Override
    public boolean doPreUpdateCredential(String userName, Object newCredential, Object oldCredential, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPreUpdateCredential(userName, newCredential, oldCredential, userStoreManager);
    }

    @Override
    public boolean doPreUpdateCredentialByAdmin(String userName, Object newCredential, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPreUpdateCredentialByAdmin(userName, newCredential, userStoreManager);
    }

    @Override
    public boolean doPreSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPreSetUserClaimValue(userName, claimURI, claimValue, profileName, userStoreManager);
    }

    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPreSetUserClaimValues(userName, claims, profileName, userStoreManager);
    }

    @Override
    public boolean doPostDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPostDeleteUser(userName, userStoreManager);
    }

    @Override
    public boolean doPostGetUserClaimValues(String userName, String[] claims, String profileName, Map<String, String> claimMap, UserStoreManager storeManager) throws UserStoreException {
        return super.doPostGetUserClaimValues(userName, claims, profileName, claimMap, storeManager);
    }

    @Override
    public boolean doPostGetUserClaimValue(String userName, String claim, List<String> claimValue, String profileName, UserStoreManager storeManager) throws UserStoreException {
        return super.doPostGetUserClaimValue(userName, claim, claimValue, profileName, storeManager);
    }

    @Override
    public boolean doPostUpdateCredential(String userName, Object credential, UserStoreManager userStoreManager) throws UserStoreException {
        return super.doPostUpdateCredential(userName, credential, userStoreManager);
    }
}
