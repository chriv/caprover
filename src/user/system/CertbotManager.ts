import ApiStatusCodes from '../../api/ApiStatusCodes'
import DockerApi from '../../docker/DockerApi'
import CaptainConstants, {
    CertbotCertCommandRule,
} from '../../utils/CaptainConstants'
import Logger from '../../utils/Logger'
import Utils from '../../utils/Utils'
import fs = require('fs-extra')
import ShellQuote = require('shell-quote')
import * as Dockerode from 'dockerode'

const WEBROOT_PATH_IN_CERTBOT = '/captain-webroot'
const WEBROOT_PATH_IN_CAPTAIN =
    CaptainConstants.captainStaticFilesDir +
    CaptainConstants.nginxDomainSpecificHtmlDir

const shouldUseStaging = false // CaptainConstants.isDebug;

const DNS_CREDENTIALS_PATH_IN_CERTBOT = '/creds.ini'

function isCertCommandSuccess(output: string) {
    // https://github.com/certbot/certbot/blob/099c6c8b240400b928d6b349e023e5e8414611e6/certbot/certbot/_internal/main.py#L516
    if (
        output.indexOf(
            'Congratulations! Your certificate and chain have been saved'
        ) >= 0
    ) {
        return true
    }

    // https://github.com/certbot/certbot/blob/f4e031f5055fc6bf8c87eb0b18f927f7f5ba36a8/certbot/certbot/_internal/main.py#L632
    if (output.indexOf('Successfully received certificate') >= 0) {
        return true
    }

    // https://github.com/certbot/certbot/blob/f4e031f5055fc6bf8c87eb0b18f927f7f5ba36a8/certbot/certbot/_internal/main.py#L1596
    if (
        output.indexOf(
            'Certificate not yet due for renewal; no action taken'
        ) >= 0
    ) {
        return true
    }

    return false
}

class CertbotManager {
    private isOperationInProcess: boolean
    private certCommandGenerator = new CertCommandGenerator(
        CaptainConstants.configs.certbotCertCommandRules ?? [],
        'certbot certonly --webroot -w ${webroot} -d ${domainName}'
    )

    constructor(private dockerApi: DockerApi) {
        this.dockerApi = dockerApi
    }

    domainValidOrThrow(domainName: string) {
        if (!domainName) {
            throw new Error('Domain Name is empty')
        }

        const RegExpression = /^[a-z0-9\.\-]*$/

        if (!RegExpression.test(domainName)) {
            throw new Error('Bad Domain Name!')
        }
    }

    getCertRelativePathForDomain(domainName: string) {
        const self = this

        self.domainValidOrThrow(domainName)

        return `/live/${domainName}/fullchain.pem`
    }

    getKeyRelativePathForDomain(domainName: string) {
        const self = this

        self.domainValidOrThrow(domainName)

        return `/live/${domainName}/privkey.pem`
    }
    enableSsl(domainName: string) {
        const self = this

        Logger.d(`Enabling SSL for ${domainName}`)

        return Promise.resolve()
            .then(function () {
                self.domainValidOrThrow(domainName)
                return self.ensureDomainHasDirectory(domainName)
            })
            .then(function () {
                const cmd = self.certCommandGenerator.getCertbotCertCommand(
                    domainName,
                    WEBROOT_PATH_IN_CERTBOT + '/' + domainName
                )

                if (shouldUseStaging) {
                    cmd.push('--staging')
                }

                return self.runCommand(cmd).then(function (output) {
                    Logger.d(output)

                    if (isCertCommandSuccess(output)) {
                        return true
                    }

                    throw ApiStatusCodes.createError(
                        ApiStatusCodes.VERIFICATION_FAILED,
                        `Unexpected output when enabling SSL for${domainName} with ACME Certbot \n ${output}`
                    )
                })
            })
    }

    public async enableSslDns01(
        domainName: string,
        emailAddress: string,
        dnsProvider: string, // Should be 'cloudflare' or other supported providers
        credsFilePathOnHost: string
    ): Promise<boolean> {
        this.domainValidOrThrow(domainName)

        if (!fs.pathExistsSync(credsFilePathOnHost)) {
            throw ApiStatusCodes.createError(
                ApiStatusCodes.STATUS_ERROR_GENERIC,
                `DNS credentials file not found at ${credsFilePathOnHost}`
            )
        }

        await this.ensureDomainHasDirectory(domainName)

        // Ensure certbot service is configured with the DNS credentials mounted
        await this.ensureCertbotServiceConfigurationForDns01(
            credsFilePathOnHost,
            DNS_CREDENTIALS_PATH_IN_CERTBOT
        )

        Logger.d(`Enabling SSL for ${domainName} using DNS-01 challenge with ${dnsProvider}`)

        const cmd = [
            'certbot',
            'certonly',
            // '--non-interactive' is added by runCommand
            '--agree-tos', // this is needed for certonly
            '--email',
            emailAddress,
            `--authenticator`,
            `dns-${dnsProvider}`, // e.g., dns-cloudflare
            `--dns-${dnsProvider}-credentials`,
            DNS_CREDENTIALS_PATH_IN_CERTBOT, // Path inside the container
            '-d',
            domainName,
        ]

        if (CaptainConstants.configs.rootSslConfig?.propagationSeconds) {
            cmd.push(`--dns-${dnsProvider}-propagation-seconds`)
            cmd.push(CaptainConstants.configs.rootSslConfig.propagationSeconds.toString())
        }

        if (shouldUseStaging) {
            cmd.push('--staging')
        }

        const output = await this.runCommand(cmd)
        Logger.d(output)

        if (isCertCommandSuccess(output)) {
            return true
        }

        throw ApiStatusCodes.createError(
            ApiStatusCodes.VERIFICATION_FAILED,
            `Unexpected output when enabling SSL for ${domainName} with ACME Certbot (DNS-01):\n${output}`
        )
    }

    private async ensureCertbotServiceConfigurationForDns01(
        credsFilePathOnHost: string,
        credsFilePathInContainer: string
    ) {
        Logger.d('Ensuring Certbot service is configured for DNS-01 challenge.')

        const serviceName = CaptainConstants.certbotServiceName
        const targetImage = CaptainConstants.configs.certbotImageName

        const serviceInspectInfo: Dockerode.ServiceInfo = await this.dockerApi.inspectService(serviceName)
        const serviceSpec: Dockerode.ServiceSpec = serviceInspectInfo.Spec! 

        let needsUpdate = false
        
        const taskTemplate = serviceSpec.TaskTemplate; // Dockerode.TaskSpec | undefined
        let currentImageInSpec: string | undefined;
        if (taskTemplate && taskTemplate.ContainerSpec) {
            currentImageInSpec = taskTemplate.ContainerSpec.Image;
        }

        // 1. Check image
        if (currentImageInSpec !== targetImage) {
            Logger.d(
                `Certbot service image requires update from ${currentImageInSpec || 'undefined'} to ${targetImage}.`
            )
            needsUpdate = true
        }

        // 2. Check mounts for DNS credentials
        // defaultMounts are IAppVolume compatible (for updateService)
        const defaultMounts: { hostPath: string; containerPath: string }[] = [
            {
                hostPath: CaptainConstants.letsEncryptEtcPath,
                containerPath: '/etc/letsencrypt',
            },
            {
                hostPath: CaptainConstants.letsEncryptLibPath,
                containerPath: '/var/lib/letsencrypt',
            },
            {
                hostPath: WEBROOT_PATH_IN_CAPTAIN,
                containerPath: WEBROOT_PATH_IN_CERTBOT,
            },
        ]

        // newCredentialMountForUpdateService is IAppVolume compatible (for updateService)
        const newCredentialMountForUpdateService = {
            hostPath: credsFilePathOnHost,
            containerPath: credsFilePathInContainer,
        }

        // currentDockerodeMounts are Dockerode.Mount[] from dockerode
        let currentDockerodeMounts: Dockerode.Mount[] = [];
        if (taskTemplate && taskTemplate.ContainerSpec) {
            currentDockerodeMounts = taskTemplate.ContainerSpec.Mounts || [];
        }
        
        // Check if the specific credential mount already exists with correct properties
        const credMountExists = currentDockerodeMounts.some(
            (m: Dockerode.Mount) => // m is a Dockerode.Mount object
                m.Target === credsFilePathInContainer && // Compare with the path in container
                m.Source === credsFilePathOnHost && // Compare with the path on host
                m.Type === 'bind' && // Check if it's a bind mount
                m.ReadOnly === true // Ensure it's read-only
        )

        const expectedTotalMounts = defaultMounts.length + 1 // All defaults plus the new one

        if (!credMountExists || currentDockerodeMounts.length !== expectedTotalMounts) {
            Logger.d(
                `Certbot service credential mount for ${credsFilePathInContainer} is missing, incorrect, or total mount count differs. Current: ${currentDockerodeMounts.length}, Expected: ${expectedTotalMounts}. Needs update.`
            )
            needsUpdate = true
        }

        if (needsUpdate) {
            Logger.d(
                `Updating Certbot service (${serviceName}) for DNS-01 challenge mounts or image.`
            )

            // finalMountsForUpdate must be IAppVolume[]
            // Start with default mounts, then add the new credential mount, ensuring it's unique by containerPath.
            let finalMountsForUpdate = defaultMounts.filter(
                (m) => m.containerPath !== newCredentialMountForUpdateService.containerPath
            )
            finalMountsForUpdate.push(newCredentialMountForUpdateService)

            await this.dockerApi.updateService(
                serviceName,
                targetImage,
                finalMountsForUpdate, // This is IAppVolume[]
                undefined, // networks - no change
                undefined, // env vars - no change
                undefined, // ports - no change
                undefined, // nodeId - no change
                undefined, // replicas - no change
                undefined, // workDir - no change
                undefined, // entrypoint - no change
                undefined, // extraHosts - no change
                undefined, // labels - no change
                undefined, // memoryBytes - no change
                undefined, // cpuShares - no change
                undefined // healthcheck - no change
            )
            Logger.d('Certbot service updated. Waiting 12 seconds for it to settle...')
            await Utils.getDelayedPromise(12000)
        } else {
            Logger.d('Certbot service configuration is already suitable for DNS-01.')
        }
    }

    ensureRegistered(emailAddress: string) {
        const self = this

        return Promise.resolve()
            .then(function () {
                // Creds used to be saved at
                // /etc/letencrypt/accounts/acme-v01.api.letsencrypt.org/directory/9fc95dbca2f0b877
                // After moving to 0.29.1, Certbot started using v2 API. and this path is no longer valid.
                // Instead, they use v02 path. However, old installations who registered with v1, will remain in the same directory
                const cmd = [
                    'certbot',
                    'register',
                    '--email',
                    emailAddress,
                    '--agree-tos',
                    '--no-eff-email',
                ]

                if (shouldUseStaging) {
                    cmd.push('--staging')
                }

                return self.runCommand(cmd)
            })
            .then(function (registerOutput) {
                if (
                    registerOutput.includes(
                        'Your account credentials have been saved in your Certbot'
                    ) ||
                    registerOutput.includes('Account registered.')
                ) {
                    return true
                }

                if (
                    registerOutput.indexOf('There is an existing account') >= 0
                ) {
                    return true
                }

                throw new Error(
                    `Unexpected output when registering with ACME Certbot \n ${registerOutput}`
                )
            })
    }

    /*
  Certificate Name: customdomain-another.hm2.caprover.com
    Domains: customdomain-another.hm2.caprover.com
    Expiry Date: 2019-03-22 04:22:55+00:00 (VALID: 81 days)
    Certificate Path: /etc/letsencrypt/live/customdomain-another.hm2.caprover.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/customdomain-another.hm2.caprover.com/privkey.pem
  Certificate Name: testing.cp.hm.caprover.com
    Domains: testing.cp.hm.caprover.com
    Expiry Date: 2019-03-21 18:42:17+00:00 (VALID: 81 days)
    Certificate Path: /etc/letsencrypt/live/testing.cp.hm.caprover.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/testing.cp.hm.caprover.com/privkey.pem
  Certificate Name: registry.cp.hm.caprover.com
    Domains: registry.cp.hm.caprover.com
    Expiry Date: 2019-03-25 04:56:45+00:00 (VALID: 84 days)
    Certificate Path: /etc/letsencrypt/live/registry.cp.hm.caprover.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/registry.cp.hm.caprover.com/privkey.pem
  Certificate Name: captain.cp.hm.caprover.com
    Domains: captain.cp.hm.caprover.com
    Expiry Date: 2019-03-20 22:25:50+00:00 (VALID: 80 days)
    Certificate Path: /etc/letsencrypt/live/captain.cp.hm.caprover.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/captain.cp.hm.caprover.com/privkey.pem
  Certificate Name: testing2.cp.hm.caprover.com
    Domains: testing2.cp.hm.caprover.com
    Expiry Date: 2019-03-21 18:42:55+00:00 (VALID: 81 days)
    Certificate Path: /etc/letsencrypt/live/testing2.cp.hm.caprover.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/testing2.cp.hm.caprover.com/privkey.pem

*/
    ensureAllCurrentlyRegisteredDomainsHaveDirs() {
        const self = this
        return Promise.resolve() //
            .then(function () {
                return self
                    .runCommand(['certbot', 'certificates'])
                    .then(function (output) {
                        const lines = output.split('\n')
                        const domains: string[] = []
                        lines.forEach((l) => {
                            if (l.indexOf('Certificate Name:') >= 0) {
                                domains.push(
                                    l.replace('Certificate Name:', '').trim()
                                )
                            }
                        })

                        return domains
                    })
            })
            .then(function (allDomains) {
                const p = Promise.resolve()
                allDomains.forEach((d) => {
                    p.then(function () {
                        return self.ensureDomainHasDirectory(d)
                    })
                })

                return p
            })
    }

    lock() {
        if (this.isOperationInProcess) {
            throw ApiStatusCodes.createError(
                ApiStatusCodes.STATUS_ERROR_GENERIC,
                'Another operation is in process for Certbot. Please wait a few seconds and try again.'
            )
        }

        this.isOperationInProcess = true
    }

    unlock() {
        this.isOperationInProcess = false
    }

    runCommand(cmd: string[]) {
        const dockerApi = this.dockerApi
        const self = this

        return Promise.resolve().then(function () {
            self.lock()

            const nonInterActiveCommand = [...cmd, '--non-interactive']
            return dockerApi
                .executeCommand(
                    CaptainConstants.certbotServiceName,
                    nonInterActiveCommand
                )
                .then(function (data) {
                    self.unlock()
                    Logger.dev(data)
                    return data
                })
                .catch(function (error) {
                    self.unlock()
                    throw error
                })
        })
    }

    ensureDomainHasDirectory(domainName: string) {
        return Promise.resolve() //
            .then(function () {
                return fs.ensureDir(`${WEBROOT_PATH_IN_CAPTAIN}/${domainName}`)
            })
    }

    renewAllCerts() {
        const self = this

        /*
        From Certbot docs:
            This command attempts to renew all previously-obtained certificates that expire in less than 30 days.
            The same plugin and options that were used at the time the certificate was originally issued will be
            used for the renewal attempt, unless you specify other plugins or options. Unlike certonly, renew
            acts on multiple certificates and always takes into account whether each one is near expiry. Because
            of this, renew is suitable (and designed) for automated use, to allow your system to automatically
            renew each certificate when appropriate. Since renew only renews certificates that are near expiry
            it can be run as frequently as you want - since it will usually take no action.
         */

        const cmd = ['certbot', 'renew']

        if (shouldUseStaging) {
            cmd.push('--staging')
        }

        return Promise.resolve() //
            .then(function () {
                return self.ensureAllCurrentlyRegisteredDomainsHaveDirs()
            })
            .then(function () {
                return self.runCommand(cmd)
            })
            .then(function (output) {
                // Ignore output :)
            })
            .catch(function (err) {
                Logger.e(err)
            })
    }

    init(myNodeId: string) {
        const dockerApi = this.dockerApi
        const self = this

        function createCertbotServiceOnNode(nodeId: string) {
            Logger.d('Creating Certbot service')

            return dockerApi
                .createServiceOnNodeId(
                    CaptainConstants.configs.certbotImageName,
                    CaptainConstants.certbotServiceName,
                    undefined,
                    nodeId,
                    undefined,
                    undefined,
                    undefined
                )
                .then(function () {
                    Logger.d('Waiting for Certbot...')
                    return Utils.getDelayedPromise(12000)
                })
        }

        return Promise.resolve()
            .then(function () {
                return fs.ensureDir(CaptainConstants.letsEncryptEtcPath)
            })
            .then(function () {
                return fs.ensureDir(CaptainConstants.letsEncryptLibPath)
            })
            .then(function () {
                return fs.ensureDir(WEBROOT_PATH_IN_CAPTAIN)
            })
            .then(function () {
                return dockerApi.isServiceRunningByName(
                    CaptainConstants.certbotServiceName
                )
            })
            .then(function (isRunning) {
                if (isRunning) {
                    Logger.d('Captain Certbot is already running.. ')

                    return dockerApi.getNodeIdByServiceName(
                        CaptainConstants.certbotServiceName,
                        0
                    )
                } else {
                    Logger.d(
                        'No Captain Certbot service is running. Creating one...'
                    )

                    return createCertbotServiceOnNode(myNodeId) //
                        .then(function () {
                            return myNodeId
                        })
                }
            })
            .then(function (nodeId) {
                if (nodeId !== myNodeId) {
                    Logger.d(
                        'Captain Certbot is running on a different node. Removing...'
                    )

                    return dockerApi
                        .removeServiceByName(
                            CaptainConstants.certbotServiceName
                        )
                        .then(function () {
                            Logger.d('Waiting for Certbot to be removed...')
                            return Utils.getDelayedPromise(10000)
                        })
                        .then(function () {
                            return createCertbotServiceOnNode(myNodeId).then(
                                function () {
                                    return true
                                }
                            )
                        })
                } else {
                    return true
                }
            })
            .then(function () {
                Logger.d('Updating Certbot service...')

                return dockerApi.updateService(
                    CaptainConstants.certbotServiceName,
                    CaptainConstants.configs.certbotImageName,
                    [
                        {
                            hostPath: CaptainConstants.letsEncryptEtcPath,
                            containerPath: '/etc/letsencrypt',
                        },
                        {
                            hostPath: CaptainConstants.letsEncryptLibPath,
                            containerPath: '/var/lib/letsencrypt',
                        },
                        {
                            hostPath: WEBROOT_PATH_IN_CAPTAIN,
                            containerPath: WEBROOT_PATH_IN_CERTBOT,
                        },
                    ],
                    // No need to certbot to be connected to the network
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    undefined
                )
            })
            .then(function () {
                return self.ensureAllCurrentlyRegisteredDomainsHaveDirs()
            })
    }
}

export default CertbotManager

export class CertCommandGenerator {
    constructor(
        private rules: CertbotCertCommandRule[],
        private defaultCommand: string
    ) {}

    private getCertbotCertCommandTemplate(domainName: string): string {
        for (const rule of this.rules) {
            if (
                rule.domain === '*' ||
                domainName === rule.domain ||
                domainName.endsWith('.' + rule.domain)
            ) {
                return rule.command ?? this.defaultCommand
            }
        }
        return this.defaultCommand
    }
    getCertbotCertCommand(domainName: string, webroot: string): string[] {
        const variables: Record<string, string> = {
            domainName,
            webroot,
        }
        const command = this.getCertbotCertCommandTemplate(domainName)
        const parsed = ShellQuote.parse(command, (key: string) => {
            return variables[key] ?? `\${${key}}`
        })
        if (parsed.some((x) => typeof x !== 'string')) {
            throw new Error(`Invalid command: ${command}`)
        }
        return parsed as string[]
    }
}
