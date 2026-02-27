use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::sol;
use alloy::transports::http::{Client, Http};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    contract INovaAppRegistry {
        struct App {
            uint256 id;
            address owner;
            bytes32 teeArch;
            address dappContract;
            string metadataUri;
            uint256 latestVersionId;
            uint256 createdAt;
            uint8 status;
            address appWallet;
        }

        struct RuntimeInstance {
            uint256 id;
            uint256 appId;
            uint256 versionId;
            address operator;
            string instanceUrl;
            bytes teePubkey;
            address teeWalletAddress;
            bool zkVerified;
            uint8 status;
            uint256 registeredAt;
        }

        function getApp(uint256 appId) external view returns (App memory);
        function getInstanceByWallet(address wallet) external view returns (RuntimeInstance memory);
        function getActiveInstances(uint256 appId) external view returns (address[] memory);
    }

    #[sol(rpc)]
    contract IKMSRegistry {
        function getOperators() external view returns (address[] memory);
        function isOperator(address account) external view returns (bool);
        function masterSecretHash() external view returns (bytes32);
    }
}

pub struct RegistryClient {
    pub nova_registry:
        INovaAppRegistry::INovaAppRegistryInstance<Http<Client>, RootProvider<Http<Client>>>,
    pub kms_registry: IKMSRegistry::IKMSRegistryInstance<Http<Client>, RootProvider<Http<Client>>>,
}

impl RegistryClient {
    pub fn new(
        rpc_url: &str,
        nova_address: &str,
        kms_address: &str,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let url = reqwest::Url::parse(rpc_url)?;
        let provider = ProviderBuilder::new().on_http(url);

        let nova_addr = Address::from_str(nova_address)?;
        let kms_addr = Address::from_str(kms_address)?;

        let nova_registry = INovaAppRegistry::new(nova_addr, provider.clone());
        let kms_registry = IKMSRegistry::new(kms_addr, provider);

        Ok(Self {
            nova_registry,
            kms_registry,
        })
    }
}
