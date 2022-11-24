import {ConfidentialClientApplication} from '@azure/msal-node';

export async function getAzureAccessToken() {
	const {AZ_CLIENT_ID, AZ_CLIENT_SECRET, AZ_TENANT_ID} = process.env;
	if (!AZ_CLIENT_ID || !AZ_CLIENT_SECRET || !AZ_TENANT_ID) {
		console.log('do AAD App registration');
		console.log('Expose an API');
		console.log('Token configuration, add something to access token (i.e. groups or roles) to force JWT token');
		console.log('Certificates & secrets, create a client secret');
		throw new Error('missing AZ_CLIENT_ID, AZ_CLIENT_SECRET or AZ_TENANT_ID env vars');
	}
	const client = new ConfidentialClientApplication({
		auth: {
			clientId: AZ_CLIENT_ID,
			clientSecret: AZ_CLIENT_SECRET,
			authority: `https://login.microsoftonline.com/${AZ_TENANT_ID}`,
		},
	});
	const scope = process.env.AZ_SCOPE || `api://${AZ_CLIENT_ID}/.default`;
	const authResult = await client.acquireTokenByClientCredential({
		scopes: [scope],
	});
	if (!authResult) {
		throw new Error('no auth result');
	}
	return authResult.accessToken;
}
