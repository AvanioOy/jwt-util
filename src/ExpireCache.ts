import {ICache} from './interfaces/ICache';

export class ExpireCache<T extends object> implements ICache<T> {
	private cache = new Map<string, {data: T; expires: number}>();
	public set(key: string, data: T, expires: number) {
		this.cache.set(key, {data, expires});
	}

	public get(key: string) {
		this.cleanExpired();
		return this.cache.get(key)?.data;
	}

	public delete(key: string): boolean {
		return this.cache.delete(key);
	}

	public clear() {
		this.cache.clear();
	}

	public size() {
		return this.cache.size;
	}

	private cleanExpired() {
		const now = new Date().getTime();
		for (const [key, value] of this.cache.entries()) {
			if (value.expires < now) {
				this.cache.delete(key);
			}
		}
	}
}
