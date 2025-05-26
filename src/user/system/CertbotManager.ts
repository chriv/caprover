import CaptainConstants from '../../utils/CaptainConstants';
import DockerApi from '../../docker/DockerApi';
import Utils from '../../utils/Utils';

class CertbotManager {
    private dockerApi: DockerApi;

    constructor(dockerApi: DockerApi) {
        this.dockerApi = dockerApi;
    }

    async enableSsl(domainName: string, email: string): Promise<void> {
        const command = [
            'certonly',
            '--non-interactive',
            '--agree-tos',
            '--email', email,
            '--webroot',
            '-w', '/captain-certbot/webroot',
            '-d', domainName,
        ];

        await this.dockerApi.executeCommand(CaptainConstants.certbotServiceName, command);
    }

    async enableSslDns01Cloudflare(domainName: string, email: string): Promise<void> {
        const cfg = CaptainConstants.configs.rootSslConfig;
        if (!cfg) throw new Error('Missing rootSslConfig');

        const certbotImage = CaptainConstants.configs.certbotImageName;
        const credentialsHostPath = cfg.credentialsFilePath;
        const credentialsContainerPath = '/etc/letsencrypt/cloudflare.ini';

        const volumes = [
            {
                hostPath: '/captain/data/letsencrypt',
                containerPath: '/etc/letsencrypt',
            },
            {
                hostPath: '/captain/data/certbot/webroot',
                containerPath: '/captain-certbot/webroot',
            },
            {
                hostPath: credentialsHostPath,
                containerPath: credentialsContainerPath,
            },
        ];

        await this.dockerApi.updateService(
            CaptainConstants.certbotServiceName, // serviceName
            certbotImage,                        // imageName
            volumes,                             // volumes
            undefined,                           // networks
            undefined,                           // ports
            undefined,                           // envVars
            undefined,                           // mounts (deprecated/unused)
            undefined                            // restartPolicy
        );

        await Utils.getDelayedPromise(12000); // allow service to update

        const command = [
            'certonly',
            '--non-interactive',
            '--agree-tos',
            '--email', email,
            '--dns-cloudflare',
            '--dns-cloudflare-credentials', credentialsContainerPath,
            '-d', domainName,
        ];

        if (cfg.propagationSeconds) {
            command.push('--dns-cloudflare-propagation-seconds', cfg.propagationSeconds.toString());
        }

        await this.dockerApi.executeCommand(CaptainConstants.certbotServiceName, command);
    }
}

export = CertbotManager;
