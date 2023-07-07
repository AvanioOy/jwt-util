/* eslint-disable sonarjs/no-duplicate-string */
import 'mocha';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as dotenv from 'dotenv';
import {IssuerManager, JwtAsymmetricDiscoveryTokenIssuer, JwtAzureMultitenantTokenIssuer, JwtManager} from '../src';
import {getAzureAccessToken} from './lib/azure';
import {getGoogleIdToken} from './lib/google';

dotenv.config();

chai.use(chaiAsPromised);

const expect = chai.expect;

describe('JwtManager', () => {
	it('should validate google id token', async () => {
		const jwt = new JwtManager(new IssuerManager([new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com'])]));
		const {isCached, body} = await jwt.verify(await getGoogleIdToken());
		expect(body).to.have.all.keys(['aud', 'azp', 'email', 'email_verified', 'exp', 'iat', 'iss', 'sub']);
		expect(isCached).to.be.eq(false);
	});
	it('should validate azure token', async () => {
		const jwt = new JwtManager(
			new IssuerManager([new JwtAzureMultitenantTokenIssuer({allowedIssuers: [`https://sts.windows.net/${process.env.AZ_TENANT_ID}/`]})]),
		);
		const token = await getAzureAccessToken();
		const {isCached, body} = await jwt.verify(token);
		expect(body).to.have.all.keys(['aud', 'iss', 'iat', 'nbf', 'exp', 'aio', 'appid', 'appidacr', 'idp', 'oid', 'rh', 'sub', 'tid', 'uti', 'ver']);
		expect(isCached).to.be.eq(false);
	});
});
