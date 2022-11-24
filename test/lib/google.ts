import {google} from 'googleapis';
import {azureMultilineEnvFix} from './common';

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
			if (!cred || !cred.access_token) {
				reject(new Error('no access token'));
			} else {
				resolve(cred.access_token);
			}
		});
	});
}

export const getGoogleIdToken = async () => {
	const body = JSON.stringify({
		audience: process.env.GOOGLE_CLIENT_EMAIL,
		delegates: [],
		includeEmail: true,
	});
	const headers = new Headers();
	headers.set('Authorization', 'Bearer ' + (await getAccessToken()));
	headers.set('Content-Type', 'application/json');
	headers.set('Content-Length', '' + body.length);
	const res = await fetch(`https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${process.env.GOOGLE_CLIENT_EMAIL}:generateIdToken`, {
		body,
		headers,
		method: 'POST',
	});
	if (res.status !== 200) {
		throw new Error('getGoogleIdToken code ' + res.status);
	}
	const data = await res.json();
	return data.token;
};
