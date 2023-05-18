/* eslint-disable @typescript-eslint/no-explicit-any */
import 'mocha';
import * as fs from 'fs';
import 'cross-fetch/polyfill';
import * as chai from 'chai';
import {JwtCertStore} from '../src/JwtCertStore';
import {JwtCertManager} from '../src/JwtCertManager';
import * as chaiAsPromised from 'chai-as-promised';

chai.use(chaiAsPromised);

const expect = chai.expect;

let googleCertKids: string[];
let certStore: JwtCertStore;

const CACHE_FILE = './test/cache.json';

const GOOGLE_ISSUER = 'https://accounts.google.com';

const symmetricKey = 'secret';

describe('JwtCertManager', () => {
	before(async () => {
		const res = await fetch('https://www.googleapis.com/oauth2/v3/certs');
		googleCertKids = (await res.json()).keys.map((key: any) => key.kid) as string[];
		certStore = new JwtCertStore();
	});
	it('should get asymmetric key from google', async () => {
		const certMgmr = new JwtCertManager(certStore);
		for (const kid of googleCertKids) {
			expect(await certMgmr.getCert(GOOGLE_ISSUER, kid)).to.be.instanceOf(Buffer);
		}
	});
	it('should get asymmetric key from google with preloading of all current certs', async () => {
		const certMgmr = new JwtCertManager(certStore);
		await certMgmr.loadIssuerCerts(GOOGLE_ISSUER); // preloading certs
		for (const kid of googleCertKids) {
			expect(await certMgmr.getCert(GOOGLE_ISSUER, kid)).to.be.instanceOf(Buffer);
		}
	});
	it('should fail to load asymmetric certs if not in validIssuers list', async () => {
		const certMgmr = new JwtCertManager(certStore, {validIssuers: [], notValidIssuerThrows: true});
		await expect(certMgmr.loadIssuerCerts(GOOGLE_ISSUER)).to.be.rejectedWith(Error, `Issuer '${GOOGLE_ISSUER}' is not in validIssuers list`);
	});
	describe('symmetric keys', () => {
		it('should get symmetric key from google', async () => {
			const issuerUrl = 'http://localhost';
			let certMgmr = new JwtCertManager(new JwtCertStore({cacheFileName: CACHE_FILE, cachePretty: true, logger: console}), {
				validIssuers: [issuerUrl],
				notValidIssuerThrows: true,
				logger: console,
			});
			const kid = '01';
			await certMgmr.addCert(issuerUrl, kid, 'symmetric', symmetricKey);
			expect(await certMgmr.getCert(issuerUrl, kid)).to.be.equal(symmetricKey);
			// rebuild certMgmr from test cache
			certMgmr = new JwtCertManager(new JwtCertStore({cacheFileName: CACHE_FILE, cachePretty: true, logger: console}), {
				validIssuers: [issuerUrl],
				notValidIssuerThrows: true,
				logger: console,
			});
			// symmetric keys shuold not be in cache
			await expect(certMgmr.getCert(issuerUrl, kid)).to.eventually.throw(Error, 'Symmetric key not found');
		});
	});

	afterEach(() => {
		if (fs.existsSync(CACHE_FILE)) {
			fs.unlinkSync(CACHE_FILE);
		}
	});
});
