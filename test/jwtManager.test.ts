/* eslint-disable sonarjs/no-duplicate-string */
import 'mocha';
import * as chai from 'chai';
import {IssuerManager} from '../src/IssuerManager';
import {JwtManager} from '../src/JwtManager';
import {JwtSymmetricTokenIssuer} from '../src/issuers/JwtSymmetricTokenIssuer';
import {JwtAsymmetricTokenIssuer} from '../src/issuers/JwtAsymmetricTokenIssuer';
import {JwtAsymmetricDiscoveryTokenIssuer} from '../src/issuers/JwtAsymmetricDiscoveryTokenIssuer';
import * as chaiAsPromised from 'chai-as-promised';
import {getGoogleIdToken} from './lib/google';

chai.use(chaiAsPromised);

const expect = chai.expect;

const ISSUER_URL = 'http://localhost';

describe('JwtManager', () => {
	describe('IssuerManager', () => {
		it('should store and get symmetric key', async () => {
			const issuer = new JwtSymmetricTokenIssuer([ISSUER_URL]);
			issuer.add(ISSUER_URL, '01', 'secret');
			const jwtManager = new IssuerManager();
			jwtManager.add(issuer);
			expect(jwtManager.issuerSolverCount(ISSUER_URL)).to.be.eq(1);
			expect(jwtManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
			expect(await jwtManager.get(ISSUER_URL, '01')).to.be.eq('secret');
			expect(await jwtManager.get(ISSUER_URL, '02')).to.be.eq(undefined);
		});
		it('should store and get asymmetric key', async () => {
			const secret = Buffer.from('secret');
			const issuer = new JwtAsymmetricTokenIssuer([ISSUER_URL]);
			issuer.add(ISSUER_URL, '01', secret);
			const jwtManager = new IssuerManager();
			jwtManager.add(issuer);
			expect(jwtManager.issuerSolverCount(ISSUER_URL)).to.be.eq(1);
			expect(jwtManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
			expect((await jwtManager.get(ISSUER_URL, '01'))?.toString()).to.be.eq('secret');
			expect(await jwtManager.get(ISSUER_URL, '02')).to.be.eq(undefined);
		});
		it('should store and get issuer asymmetric key', async () => {
			const issuer = new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com']);
			const jwtManager = new IssuerManager();
			jwtManager.add(issuer);
			expect(jwtManager.issuerSolverCount('https://accounts.google.com')).to.be.eq(1);
			expect(jwtManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
			await issuer.load('https://accounts.google.com');
			const keyIds = await issuer.listKeyIds('https://accounts.google.com');
			expect(keyIds.length).to.be.greaterThan(0);
			const buffer = await jwtManager.get('https://accounts.google.com', keyIds[0]);
			expect(buffer).to.be.instanceOf(Buffer);
		});
	});
	describe('IssuerManager', () => {
		it('should validate google id token', async () => {
			const jwt = new JwtManager(new IssuerManager([new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com'])]));
			const payload = await jwt.verify(await getGoogleIdToken());
			console.log(payload);
		});
	});
});
