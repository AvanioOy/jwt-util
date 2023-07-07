/* eslint-disable sonarjs/no-duplicate-string */
import 'mocha';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as dotenv from 'dotenv';
import {IssuerManager, JwtAsymmetricDiscoveryTokenIssuer, JwtAsymmetricTokenIssuer, JwtSymmetricTokenIssuer} from '../src';

dotenv.config();

chai.use(chaiAsPromised);

const expect = chai.expect;

const ISSUER_URL = 'http://localhost';

describe('IssuerManager', () => {
	it('should store and get symmetric key', async () => {
		const issuer = new JwtSymmetricTokenIssuer([ISSUER_URL]);
		issuer.add(ISSUER_URL, '01', 'secret');
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount(ISSUER_URL)).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		expect(await issuerManager.get(ISSUER_URL, '01')).to.be.eq('secret');
		expect(await issuerManager.get(ISSUER_URL, '02')).to.be.eq(undefined);
	});
	it('should store and get asymmetric key', async () => {
		const issuer = new JwtAsymmetricTokenIssuer([ISSUER_URL]);
		issuer.add(ISSUER_URL, '01', Buffer.from('secret'));
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount(ISSUER_URL)).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		expect((await issuerManager.get(ISSUER_URL, '01'))?.toString()).to.be.eq('secret');
		expect(await issuerManager.get(ISSUER_URL, '02')).to.be.eq(undefined);
	});
	it('should store and get issuer asymmetric key', async () => {
		const issuer = new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com']);
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount('https://accounts.google.com')).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		await issuer.load('https://accounts.google.com');
		const keyIds = await issuer.listKeyIds('https://accounts.google.com');
		expect(keyIds.length).to.be.greaterThan(0);
		const buffer = await issuerManager.get('https://accounts.google.com', keyIds[0]);
		expect(buffer).to.be.instanceOf(Buffer);
	});
});
