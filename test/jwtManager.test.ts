import * as dotenv from 'dotenv';
import {describe, expect, it} from 'vitest';
import {z} from 'zod';
import {IssuerManager, JwtAsymmetricDiscoveryTokenIssuer, JwtAzureMultiTenantTokenIssuer, JwtManager} from '../src';
import {getAzureAccessToken, haveAzureEnvVariables} from './lib/azure';
import {getGoogleIdToken, haveGoogleEnvVariables} from './lib/google';

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
	it('should validate google id token', {skip: !haveGoogleEnvVariables()}, async () => {
		const jwt = new JwtManager(new IssuerManager([new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com'])]));
		const {isCached, body} = await jwt.verify(await getGoogleIdToken(), undefined, (body) => googleIdTokenSchema.strict().parse(body));
		expect(body).to.have.all.keys(['aud', 'azp', 'email', 'email_verified', 'exp', 'iat', 'iss', 'sub']);
		expect(isCached).to.be.eq(false);
	});
	it('should validate azure token', {skip: !haveAzureEnvVariables()}, async () => {
		const jwt = new JwtManager(
			new IssuerManager([new JwtAzureMultiTenantTokenIssuer({allowedIssuers: [`https://sts.windows.net/${String(process.env.AZ_TENANT_ID)}/`]})]),
		);
		const token = await getAzureAccessToken();
		const {isCached, body} = await jwt.verify(token);
		expect(body).to.have.all.keys(['aud', 'iss', 'iat', 'nbf', 'exp', 'aio', 'appid', 'appidacr', 'idp', 'oid', 'rh', 'sub', 'tid', 'uti', 'ver', 'xms_ftd']);
		expect(isCached).to.be.eq(false);
	});
});
