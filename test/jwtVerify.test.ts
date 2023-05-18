/* eslint-disable sonarjs/no-duplicate-string */
/* eslint-disable no-unused-expressions */
/* eslint-disable import/first */
import * as dotenv from 'dotenv';
import * as fs from 'fs';
dotenv.config();
process.env.NODE_ENV = 'testing';
import {expect} from 'chai';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import 'cross-fetch/polyfill';
import * as jwt from 'jsonwebtoken';
import 'mocha';
import {jwtBearerVerify, jwtVerify, jwtHaveIssuer, testGetCache, jwtDeleteKid} from '../src';
import {jwtVerifyPromise} from '../src/lib/jwt';
import {buildCertFrame} from '../src/lib/rsaPublicKeyPem';
import {JwtHeaderError} from '../src/lib/JwtHeaderError';
import {JwtCertManager} from '../src/JwtCertManager';
import {JwtCertStore} from '../src/JwtCertStore';
import {getGoogleIdToken} from './lib/google';
import {getAzureAccessToken} from './lib/azure';

// tslint:disable: no-unused-expression
chai.use(chaiAsPromised);

let GOOGLE_ID_TOKEN: string;
let AZURE_ACCESS_TOKEN: string;
let icl: JwtCertManager;

describe('jwtUtil', () => {
	before(async function () {
		this.timeout(30000);
		AZURE_ACCESS_TOKEN = await getAzureAccessToken();
		GOOGLE_ID_TOKEN = await getGoogleIdToken();
	});
	describe('jwtVerifyPromise', () => {
		it('should fail internal jwtVerifyPromise with broken data', async () => {
			await expect(jwtVerifyPromise('qwe', 'qwe')).to.be.eventually.rejectedWith(Error, 'jwt malformed');
		});
	});
	describe('jwtVerify', () => {
		it('should fail if broken token', async () => {
			await expect(jwtVerify('asd')).to.be.eventually.rejectedWith(Error, "Can't decode token");
		});
		it('should fail is issuer url is missing', async () => {
			const test = jwt.sign({}, 'test');
			await expect(jwtVerify(test)).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: missing issuer parameter');
		});
		it('should fail is kid is missing', async () => {
			const test = jwt.sign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(test)).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: missing kid parameter');
		});
		it('should fail if auth type is not Bearer', async () => {
			const test = jwt.sign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(`Basic ${test}`)).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: wrong authentication header type');
		});
		it('should not load issuer certs if not allowed', async () => {
			expect(await jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			await expect(jwtVerify(GOOGLE_ID_TOKEN, {issuer: []})).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: issuer is not valid');
			expect(await jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
		});
	});
	describe('cache', () => {
		it('Test expire cache', () => {
			const cache = testGetCache();
			cache.set('test', {none: 'test'}, new Date(Date.now() - 1000));
			expect(cache.size()).to.be.eq(1);
			expect(cache.get('test')).to.be.eq(undefined); // shoud remove test as it's expired
			expect(cache.size()).to.be.eq(0);
		});
	});
	describe('tokens', () => {
		it('Test Google IdToken', async function () {
			this.slow(100);
			expect(await jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.null;
			expect(isCached).to.be.eq(false);
			expect(await jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string);
			expect(body).not.to.be.null;
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async function () {
			this.slow(5);
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN as string);
			}
		});
		it('Test Google token as Bearer Token', async () => {
			const {body, isCached} = await jwtBearerVerify<{test?: string}>('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.undefined;
			expect(body.aud).not.to.be.undefined;
			expect(body.exp).not.to.be.undefined;
			expect(body.iat).not.to.be.undefined;
			expect(body.iss).not.to.be.undefined;
			expect(body.sub).not.to.be.undefined;
			expect(body.test).to.be.undefined;
			expect(isCached).to.be.eq(true);
		});
		it('Test non Bearer auth', async () => {
			try {
				await jwtBearerVerify('Basic some:fun');
				throw new Error("should not happen as we don't have parameters");
			} catch (err) {
				// ok
			}
		});
		it('Test non issuer token ', async () => {
			const test = jwt.sign({test: 'asd'}, 'secret');
			try {
				await jwtVerify(test);
				throw new Error("should not happen as we don't have parameters");
			} catch (err) {
				// ok
			}
		});
		it('Test non-valid issuer', async () => {
			try {
				await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['not_valid_issuer']});
				throw new Error("should not happen as we don't have parameters");
			} catch (err) {
				// ok
			}
		});
		it('Test delete kid and check force reload', async () => {
			const decoded = jwt.decode(GOOGLE_ID_TOKEN, {complete: true}) as any;
			await jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			await jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.null;
		});
		it('test Azure ID Token ', async function () {
			this.slow(500);
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.null;
		});
		after(async () => {
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
		});
	});
	describe('test IssuerCertLoader', () => {
		before(async () => {
			icl = new JwtCertManager(new JwtCertStore());
		});
		it('should throw if issuer is not found (hostname error)', async function () {
			this.timeout(10000);
			await expect(icl.getCert('https://123qweasdqwe123zzz/uuaaakkk/', 'unknown')).to.be.rejected;
		});
		it('should throw if issuer is not found (json error)', async () => {
			await expect(icl.getCert('https://google.com', 'unknown')).to.be.rejected;
		});
		it('should throw when get cert for unknown kid ', async () => {
			await expect(icl.getCert('https://accounts.google.com', 'unknown')).to.be.rejectedWith(
				"no key Id 'unknown' found for issuer 'https://accounts.google.com'",
			);
		});
	});
	describe('test buildCertFrame', () => {
		it('should get RSA PUBLIC key structure as Buffer', async () => {
			const data =
				'MIIBCgKCAQEA18uZ3P3IgOySlnOsxeIN5WUKzvlm6evPDMFbmXPtTF0GMe7tD2JPfai2UGn74s7AFwqxWO5DQZRu6VfQUux8uMR4J7nxm1Kf//7pVEVJJyDuL5a8PARRYQtH68w+0IZxcFOkgsSdhtIzPQ2jj4mmRzWXIwh8M/8pJ6qiOjvjF9bhEq0CC/f27BnljPaFn8hxY69pCoxenWWqFcsUhFZvCMthhRubAbBilDr74KaXS5xCgySBhPzwekD9/NdCUuCsdqavd4T+VWnbplbB8YsC+R00FptBFKuTyT9zoGZjWZilQVmj7v3k8jXqYB2nWKgTAfwjmiyKz78FHkaE+nCIDwIDAQAB';
			expect(buildCertFrame(data)).to.be.a.instanceof(Buffer);
		});
		it('should fail if not correct Buffer', async () => {
			expect(buildCertFrame.bind(null, '')).to.be.throw('Cert data error');
		});
	});
});
