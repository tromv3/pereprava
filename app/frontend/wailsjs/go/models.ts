export namespace backup {
	
	export class Header {
	    format: string;
	    version: number;
	    created: string;
	    server: string;
	    host: string;
	    n: number;
	    r: number;
	    p: number;
	    salt: number[];
	    nonce: number[];
	
	    static createFrom(source: any = {}) {
	        return new Header(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.format = source["format"];
	        this.version = source["version"];
	        this.created = source["created"];
	        this.server = source["server"];
	        this.host = source["host"];
	        this.n = source["n"];
	        this.r = source["r"];
	        this.p = source["p"];
	        this.salt = source["salt"];
	        this.nonce = source["nonce"];
	    }
	}

}

export namespace main {
	
	export class ClientRequest {
	    link: string;
	    serverId: string;
	    user: string;
	    systemProxy: boolean;
	    tun: boolean;
	    country: string;
	
	    static createFrom(source: any = {}) {
	        return new ClientRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.link = source["link"];
	        this.serverId = source["serverId"];
	        this.user = source["user"];
	        this.systemProxy = source["systemProxy"];
	        this.tun = source["tun"];
	        this.country = source["country"];
	    }
	}
	export class ClientInfo {
	    running: boolean;
	    name: string;
	    host: string;
	    socksPort: number;
	    httpPort: number;
	    systemProxy: boolean;
	    tun: boolean;
	    country: string;
	    admin: boolean;
	    error: string;
	    log: string[];
	    saved: ClientRequest;
	
	    static createFrom(source: any = {}) {
	        return new ClientInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.socksPort = source["socksPort"];
	        this.httpPort = source["httpPort"];
	        this.systemProxy = source["systemProxy"];
	        this.tun = source["tun"];
	        this.country = source["country"];
	        this.admin = source["admin"];
	        this.error = source["error"];
	        this.log = source["log"];
	        this.saved = this.convertValues(source["saved"], ClientRequest);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class ServerInput {
	    id: string;
	    name: string;
	    host: string;
	    port: number;
	    user: string;
	    authType: string;
	    keyPath: string;
	    password: string;
	    passphrase: string;
	    sudoPassword: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.authType = source["authType"];
	        this.keyPath = source["keyPath"];
	        this.password = source["password"];
	        this.passphrase = source["passphrase"];
	        this.sudoPassword = source["sudoPassword"];
	    }
	}
	export class ServerView {
	    id: string;
	    name: string;
	    host: string;
	    port: number;
	    user: string;
	    authType: string;
	    keyPath: string;
	    fingerprint: string;
	    hasPassword: boolean;
	    hasSudo: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ServerView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.authType = source["authType"];
	        this.keyPath = source["keyPath"];
	        this.fingerprint = source["fingerprint"];
	        this.hasPassword = source["hasPassword"];
	        this.hasSudo = source["hasSudo"];
	    }
	}

}

