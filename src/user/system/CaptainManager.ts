import Logger from '../../utils/Logger';
import CaptainConstants from '../../utils/CaptainConstants';
import CertbotManager from './CertbotManager';
// other imports...

class CaptainManager {
    // ... existing methods ...

    enableSsl(domainName: string, emailAddress: string): Promise<void> {
        Logger.d(`Enabling SSL for ${domainName} using email ${emailAddress}`);

        const rootSslConfig = CaptainConstants.configs.rootSslConfig;

        if (
            rootSslConfig &&
            rootSslConfig.challengeType === 'dns-01' &&
            rootSslConfig.dnsProvider === 'cloudflare'
        ) {
            return CertbotManager.enableSslDns01Cloudflare(domainName, emailAddress);
        }

        // Existing HTTP-01 flow (unchanged)
        return CertbotManager.enableSsl(domainName, emailAddress);
    }

    // ... any remaining methods ...
}

export = new CaptainManager();
