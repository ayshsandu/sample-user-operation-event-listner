package org.wso2.carbon.sample.user.operation.event.listener;

import org.wso2.carbon.identity.mgt.IdentityMgtConfig;
import org.wso2.carbon.identity.mgt.constants.IdentityMgtConstants;
import org.wso2.carbon.user.api.RealmConfiguration;

public class CustomIdentityMgtConfig extends IdentityMgtConfig {

    private static CustomIdentityMgtConfig customIdentityMgtConfig;

    public CustomIdentityMgtConfig(RealmConfiguration configuration) {
        super(configuration);
    }

    public static CustomIdentityMgtConfig getInstance(RealmConfiguration configuration) {
        customIdentityMgtConfig = new CustomIdentityMgtConfig(configuration);
        return customIdentityMgtConfig;
    }

    public static CustomIdentityMgtConfig getInstance() {
        return customIdentityMgtConfig;
    }

    public int getAuthPolicyMaxLoginAttempts(String domain) {
        String maxLoginAttemptProperty = super.getProperty(domain + "." + IdentityMgtConstants.PropertyConfig
                .AUTH_POLICY_ACCOUNT_LOCKING_FAIL_ATTEMPTS);
        if (maxLoginAttemptProperty != null) {
            return Integer.parseInt(maxLoginAttemptProperty.trim());
        } else {
            return super.getAuthPolicyMaxLoginAttempts();
        }
    }

    public int getAuthPolicyLockingTime(String domain) {
        String maxLoginAttemptProperty = super.getProperty(domain + "." + IdentityMgtConstants.PropertyConfig
                .AUTH_POLICY_ACCOUNT_LOCKING_TIME);
        if (maxLoginAttemptProperty != null) {
            return Integer.parseInt(maxLoginAttemptProperty.trim());
        } else {
            return super.getAuthPolicyLockingTime();
        }
    }
}
