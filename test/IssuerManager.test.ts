import * as dotenv from 'dotenv';
import {describe, expect, it} from 'vitest';
import {IssuerManager, JwtAsymmetricDiscoveryTokenIssuer, JwtAsymmetricTokenIssuer, JwtSymmetricTokenIssuer} from '../src';

dotenv.config();

const issuerUrl = 'http://localhost';

describe('IssuerManager', () => {
	it('should store and get symmetric key', async () => {
		const issuer = new JwtSymmetricTokenIssuer([issuerUrl]);
		issuer.add(issuerUrl, '01', 'secret');
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		expect(await issuerManager.get(issuerUrl, '01')).to.be.eq('secret');
		expect(await issuerManager.get(issuerUrl, '02')).to.be.eq(undefined);
	});
	it('should store and get asymmetric key', async () => {
		const issuer = new JwtAsymmetricTokenIssuer([issuerUrl]);
		issuer.add(issuerUrl, '01', Buffer.from('secret'));
		const issuerManager = new IssuerManager();
		issuerManager.add(issuer);
		expect(issuerManager.issuerSolverCount(issuerUrl)).to.be.eq(1);
		expect(issuerManager.issuerSolverCount('http://localhost2')).to.be.eq(0);
		expect((await issuerManager.get(issuerUrl, '01'))?.toString()).to.be.eq('secret');
		expect(await issuerManager.get(issuerUrl, '02')).to.be.eq(undefined);
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
