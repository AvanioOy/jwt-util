/* eslint-disable sonarjs/no-duplicate-string */
import * as dotenv from 'dotenv';
import {describe, expect, it} from 'vitest';
import {IssuerManager, JwtAsymmetricDiscoveryTokenIssuer, JwtAzureMultitenantTokenIssuer, JwtManager} from '../src';
import {getAzureAccessToken} from './lib/azure';
import {getGoogleIdToken} from './lib/google';
import {z} from 'zod';

dotenv.config();

const googleIdTokenSchema = z.object({
	aud: z.string(),
	azp: z.string(),
	email: z.string(),
	email_verified: z.boolean(),
	exp: z.number(),
	iat: z.number(),
	iss: z.string(),
	sub: z.string(),
});

describe('JwtManager', () => {
	it('should validate google id token', async () => {
		const jwt = new JwtManager(new IssuerManager([new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com'])]));
		const {isCached, body} = await jwt.verify(await getGoogleIdToken(), undefined, (body) => googleIdTokenSchema.strict().parse(body));
		expect(body).to.have.all.keys(['aud', 'azp', 'email', 'email_verified', 'exp', 'iat', 'iss', 'sub']);
		expect(isCached).to.be.eq(false);
	});
	it('should validate azure token', async () => {
		const jwt = new JwtManager(
			new IssuerManager([new JwtAzureMultitenantTokenIssuer({allowedIssuers: [`https://sts.windows.net/${String(process.env.AZ_TENANT_ID)}/`]})]),
		);
		const token = await getAzureAccessToken();
		const {isCached, body} = await jwt.verify(token);
		expect(body).to.have.all.keys(['aud', 'iss', 'iat', 'nbf', 'exp', 'aio', 'appid', 'appidacr', 'idp', 'oid', 'rh', 'sub', 'tid', 'uti', 'ver']);
		expect(isCached).to.be.eq(false);
	});
});
