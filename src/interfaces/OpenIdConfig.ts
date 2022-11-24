interface IOpenIdConfig {
	jwks_uri: string;
}
export interface IOpenIdConfigCache extends IOpenIdConfig {
	expires: number;
}
