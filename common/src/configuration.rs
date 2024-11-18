use serde_aux::field_attributes::deserialize_number_from_string;

pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} us not a supported environment. Use either `local` or `production`",
                other
            )),
        }
    }
}
#[derive(serde::Deserialize, Clone, Debug)]
pub struct Settings {
    pub general: GeneralSettings,
    pub application: ApplicationSettings,
    pub sequencer: ClientSettings,
    pub client: ClientSettings,
}

impl Settings {
    pub fn log_level(&self) -> String {
        self.general.log_level.to_string()
    }
}

#[derive(serde::Deserialize, Clone, Debug)]
pub struct GeneralSettings {
    pub log_level: String,
}

#[derive(serde::Deserialize, Clone, Debug)]
pub struct ApplicationSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub base_url: String,
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine current directory");
    let configuration_directory = base_path.join("configuration");

    let environment: Environment = std::env::var("APP_ENVIRONMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to parse APP_ENVIRONMENT");

    let settings = config::Config::builder()
        .add_source(config::File::from(configuration_directory.join("base")).required(true))
        .add_source(
            config::File::from(configuration_directory.join(environment.as_str())).required(true),
        )
        .add_source(config::Environment::with_prefix("app").separator("__"))
        .build()?; // Build the configuration

    settings.try_deserialize::<Settings>()
}

#[derive(serde::Deserialize, Clone, Debug)]
pub struct ClientSettings {
    pub base_url: String,
    pub timeout_milliseconds: u64,
}

impl ClientSettings {
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.timeout_milliseconds)
    }
}
