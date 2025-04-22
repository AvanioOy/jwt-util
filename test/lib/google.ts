import {google} from 'googleapis';
import {azureMultilineEnvFix} from './common';

/**
 * Check if GOOGLE_CLIENT_EMAIL and GOOGLE_CLIENT_KEY env vars are set
 * @returns true if env vars are set
 */
export function haveGoogleEnvVariables() {
	const {GOOGLE_CLIENT_EMAIL, GOOGLE_CLIENT_KEY} = process.env;
	return Boolean(GOOGLE_CLIENT_EMAIL && GOOGLE_CLIENT_KEY);
}

/**
 * Get google access token
 * @returns google access token
 */
function getAccessToken(): Promise<string> {
	const clientKey = azureMultilineEnvFix(process.env.GOOGLE_CLIENT_KEY);
	return new Promise((resolve, reject) => {
		const jwtClient = new google.auth.JWT(
			process.env.GOOGLE_CLIENT_EMAIL,
			undefined,
			clientKey,
			['openid', 'https://www.googleapis.com/auth/cloud-platform'],
			undefined,
		);
		jwtClient.authorize((err, cred) => {
			if (err) {
				reject(err);
				return;
			}
			if (!cred?.access_token) {
				reject(new Error('no access token'));
			} else {
				resolve(cred.access_token);
			}
		});
	});
}

/**
 * Get google id token
 * @returns google id token
 */
export async function getGoogleIdToken() {
	const body = JSON.stringify({
		audience: process.env.GOOGLE_CLIENT_EMAIL,
		delegates: [],
		includeEmail: true,
	});
	const headers = new Headers();
	headers.set('Authorization', 'Bearer ' + (await getAccessToken()));
	headers.set('Content-Type', 'application/json');
	headers.set('Content-Length', body.length.toString());
	const res = await fetch(`https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${String(process.env.GOOGLE_CLIENT_EMAIL)}:generateIdToken`, {
		body,
		headers,
		method: 'POST',
	});
	if (res.status !== 200) {
		throw new Error(`getGoogleIdToken code ${res.status.toString()}`);
	}
	const data = (await res.json()) as {token: string};
	return data.token;
}
