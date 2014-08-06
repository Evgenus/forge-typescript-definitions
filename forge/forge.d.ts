declare module forge {

    module util {
        function setImmediate(func: Function): number;
        function nextTick(func: Function): number;
        function isArray(x: any): boolean;
        function isArrayBuffer(x: any): boolean;
        function isArrayBufferView(x: any): boolean;

        interface BufferInterface<T> {
            length(): number;
            isEmpty(): boolean;
            putByte(b: number): T;
            fillWithByte(b: number, n: number): T;

            putString(str: string): T;

            putInt16(i: number): T;
            putInt24(i: number): T;
            putInt32(i: number): T;

            putInt16Le(i: number): T;
            putInt24Le(i: number): T;
            putInt32Le(i: number): T;

            putInt(i: number, n: number): T;
            putSignedInt(i: number, n: number): T;

            getByte(): number;

            getInt16(): number;
            getInt24(): number;
            getInt32(): number;

            getInt16Le(): number;
            getInt24Le(): number;
            getInt32Le(): number;

            getInt(n: number): number;
            getSignedInt(n: number): number;

            getBytes(count: number): string;
            bytes(count: number): string;
            at(i: number): number;
            setAt(i: number, b: number): T;
            last(): number;
            copy(): T;

            compact(): T;
            clear(): T;
            truncate(count: number): T;
            toHex(): string;
            toString(encoding?: number): string
        }

        interface ByteBuffer extends BufferInterface<ByteBuffer> {
            putBytes(bytes: string): ByteBuffer;
            putBuffer<T>(buffer: BufferInterface<T>): ByteBuffer;
        }

        interface ByteBufferStatic {
            new (): ByteBuffer;
            new (b: string): ByteBuffer;
            new (b: ArrayBuffer): ByteBuffer;
            new (b: ArrayBufferView): ByteBuffer;
            new <T>(b: Array<T>): ByteBuffer;
            new (b: ByteBuffer): ByteBuffer;
        }

        var ByteBuffer: ByteBufferStatic;
        var ByteStringBuffer: ByteBufferStatic;

        interface DataBuffer extends BufferInterface<DataBuffer> {
            accommodate(amount: number, growSize?: number): DataBuffer;

            putBytes(bytes: string, encoding?: string): DataBuffer;
            putBytes(bytes: DataBuffer): DataBuffer;
            putBytes(bytes: ArrayBuffer, encoding?: string): DataBuffer;
            putBytes(bytes: ArrayBufferView, encoding?: string): DataBuffer;
            putBytes<T>(bytes: Array<T>, encoding?: string): DataBuffer;

            putBuffer(bytes: string): DataBuffer;
            putBuffer(bytes: DataBuffer): DataBuffer;
            putBuffer(bytes: ArrayBuffer): DataBuffer;
            putBuffer(bytes: ArrayBufferView): DataBuffer;
            putBuffer<T>(bytes: Array<T>): DataBuffer;
        }

        interface DataBufferOptions {
            readOffset?: number;
            growSize?: number;
            writeOffset?: number;
            encoding?: string;
        }

        interface DataBufferStatic {
            new (): DataBuffer;
            new (b: string, options?: DataBufferOptions): DataBuffer;
            new (b: DataBuffer, options?: DataBufferOptions): DataBuffer;
            new (b: ArrayBuffer, options?: DataBufferOptions): DataBuffer;
            new (b: ArrayBufferView, options?: DataBufferOptions): DataBuffer;
        }

        var DataBuffer: DataBufferStatic;

        function createBuffer(input: string, encoding?: string): ByteBuffer;
        function fillString(c: string, n: number): string;
        function xorBytes(s1: string, s2: string, n: number);
        function hexToBytes(hex: string): string;
        function bytesToHex(bytes: string): string;
        function int32ToBytes(i: number): string;
        function encode64(input: string, maxline?: number): string;
        function decode64(input: string): string;
        function encodeUtf8(str: string): string;
        function decodeUtf8(str: string): string;

        module binary {
            var raw: {
                encode(bytes: string): string;
                decode(str: string): Uint8Array;
                decode(str: string, output: Uint8Array, offset?: number): number;
            }
            var hex: {
                encode(bytes: string): string;
                decode(str: string): Uint8Array;
                decode(str: string, output: Uint8Array, offset?: number): number;
            }
            var base64: {
                encode(bytes: string, maxline?: number): string;
                decode(str: string): Uint8Array;
                decode(str: string, output: Uint8Array, offset?: number): number;
            }
        }
        module text {
            var utf8: {
                encode(str: string): Uint8Array;
                encode(str: string, output: Uint8Array, offset?: number): number;
                decode(bytes: string): string;
            }
            var utf16: {
                encode(str: string): Uint8Array;
                encode(str: string, output: Uint8Array, offset?: number): number;
                decode(bytes: string): string;
            }
        }

        interface FlashInterface {
            deflate(data: string): string;
            inflate(data: string): any;

            removeItem(id: string): void;
            setItem(id: string, obj: any): void;
            getItem(id: string): any;

            init: boolean;
        }

        function deflate(api: FlashInterface, bytes: string, raw: boolean): string;
        function inflate(api: FlashInterface, bytes: string, raw: boolean): string;

        function setItem(api: FlashInterface, id: string, key: string, data: Object, location: string[]): void;
        function getItem(api: FlashInterface, id: string, key: string, location: string[]): Object;
        function removeItem(api: FlashInterface, id: string, key: string, location: string[]): void;
        function clearItems(api: FlashInterface, id: string, location: string[]): void;

        interface URLParts {
            full: string;
            scheme: string;
            host: string;
            fullHost: string;
            port: number;
            path: string;
        }

        function parseUrl(str: string): URLParts;

        function getQueryVariables(query?: string): Object;

        interface FragmentParts {
            pathString: string;
            queryString: string;
            path: string[];
            query: Object;
        }

        function parseFragment(fragment: string): Object;

        interface Request {
            path: string;
            query: string;
            getPath(): string[];
            getPath(i: number): string;
            getQuery(): Object;
            getQuery(k: string): string[];
            getQuery(k: string, i: number): string;
            getQueryLast(k: string, _default?: string): string;
        }

        function makeRequest(reqString: string): Request;

        function makeLink(path: string, query?: Object, fragment?: string): string;
        function makeLink(path: string[], query?: Object, fragment?: string): string;
        function setPath(object: Object, keys: string[], value: string): void;
        function getPath(object: Object, keys: string[], _default?: string): string;
        function deletePath(object: Object, keys: string[]): void;
        function isEmpty(object: Object): boolean;
        function format(format: string, v1?: any, v2?: any, v3?: any, v4?: any, v5?: any, v6?: any, v7?: any, v8?: any): string;
        function formatNumber(num: number, decimals?: number, dec_point?: string, thousands_sep?: string): string;
        function formatSize(size: number): string;
        function bytesFromIP(ip: string): ByteBuffer;
        function bytesFromIPv4(ip: string): ByteBuffer;
        function bytesFromIPv6(ip: string): ByteBuffer;
        function bytesToIP(bytes: ByteBuffer): string;
        function bytesToIPv4(bytes: ByteBuffer): string;
        function bytesToIPv6(bytes: ByteBuffer): string;

        interface EstimateCoresOptions {
            update?: boolean;
        }
        function estimateCores(options: EstimateCoresOptions, callback: (err: Error, max: number) => void): void;
    }

    interface Hash<T> {
        algorithm: string;
        blockLength: number;
        digestLength: number;
        messageLength: number;
        messageLength64: number[]; // array of 2 numbers

        start(): T;
        update(msg: string, encoding?: string): T;
        digest(): forge.util.ByteBuffer;
    }

    interface MD5 extends Hash<MD5> {
    }

    interface SHA1 extends Hash<SHA1> {
    }

    interface SHA224 extends Hash<SHA224> {
    }

    interface SHA256 extends Hash<SHA256> {
    }

    interface SHA384 extends Hash<SHA384> {
    }

    interface SHA512 extends Hash<SHA512> {
    }

    module md5 {
        function create(): MD5;
    }

    module sha1 {
        function create(): SHA1;
    }

    module sha224 {
        function create(): SHA224;
    }

    module sha256 {
        function create(): SHA256;
    }

    module sha384 {
        function create(): SHA384;
    }

    module sha512 {
        export import sha384 = forge.sha384;
        export import sha224 = forge.sha224;
        function create(): SHA512;
    }

    module md {
        module algorithms {
            export import md5 = forge.md5;
            export import sha1 = forge.sha1;
            export import sha256 = forge.sha256;
            export import sha384 = forge.sha384;
            export import sha512 = forge.sha512;
        }
        export import md5 = forge.md5;
        export import sha1 = forge.sha1;
        export import sha256 = forge.sha256;
        export import sha384 = forge.sha384;
        export import sha512 = forge.sha512;
    }

    interface MaskGenerator {
        generate(seed: string, maskLen: number): string;
    }

    interface MGF1 extends MaskGenerator {
    }

    module mgf1 {
        function create<T>(md: Hash<T>): MGF1;
    }

    module mgf {
        export import mgf1 = forge.mgf1;
    }

    interface HMAC {
        start(): void;
        start<T>(md: Hash<T>): void;
        start<T>(md: Hash<T>, key: string): void;
        start<T>(md: Hash<T>, key: number[]): void;
        start<T>(md: Hash<T>, key: util.ByteBuffer): void;
        start(md: string): void;
        start(md: string, key: string): void;
        start(md: string, key: number[]): void;
        start(md: string, key: util.ByteBuffer): void;

        update(bytes: string): void;

        getMac(): util.ByteBuffer;
    }

    module hmac {
        function create(): HMAC;
    }

    interface BlockCipherStartParams {
        output?: util.ByteBuffer
        iv: any; // string | number[] | ByteBuffer
        additionalData?: string;
        tagLength?: number;
    }

    interface PaddingFunction {
        (blockSize: number, buffer: util.ByteBuffer, decrypt: boolean): boolean;
    }

    interface Cipher {
        output: util.ByteBuffer;
        mode: cipher.modes.BlockMode;
        start(options: BlockCipherStartParams): void;
        update(input: util.ByteBuffer): void;
        finish(pad?: PaddingFunction): boolean;
    }

    module cipher {
        interface AlgorithmsDictionary {
            [name: string]: modes.BlockModeFactory<any>;
        }

        var algorithms: AlgorithmsDictionary;

        interface BlockCipherOptions {
            algorithm: string;
            key: any; // string | number[] | ByteBuffer
            decrypt: boolean;
        }

        class BlockCipher implements Cipher {
            constructor(options: BlockCipherOptions);

            output: util.ByteBuffer;
            mode: cipher.modes.BlockMode;
            start(options: BlockCipherStartParams): void;
            update(input: util.ByteBuffer): void;
            finish(pad?: PaddingFunction): boolean;
        }

        function createCipher(algorithm: string, key: string): BlockCipher;
        function createDecipher(algorithm: string, key: string): BlockCipher;
        function registerAlgorithm<T>(name, algorithm: modes.BlockModeFactory<T>): void;
        function getAlgorithm(name: string): modes.BlockModeFactory<any>;
        function getAlgorithm<T>(name: string): modes.BlockModeFactory<T>;

        module modes {
            interface BlockModeOptions {
                cipher: Cipher;
                blockSize: number;
            }

            interface EncryptionOptions {
                iv: any; // string | number[] | ByteBuffer
                additionalData: string;
                tagLength: number;
            }

            interface BlockMode {
                name: string;
                cipher: Cipher;
                blockSize: number;
                tag: util.ByteBuffer;
                start(options: EncryptionOptions): void;
                encrypt(input: util.ByteBuffer, output: util.ByteBuffer): void;
                decrypt(input: util.ByteBuffer, output: util.ByteBuffer): void;
            }

            interface PaddingOptions {
            }

            interface UnpaddingOptions {
                overflow: number;
            }

            interface ECB extends BlockMode {
                pad(input: util.ByteBuffer, options: PaddingOptions): boolean;
                unpad(input: util.ByteBuffer, options: UnpaddingOptions): boolean;
            }

            interface CBC extends BlockMode {
                pad(input: util.ByteBuffer, options: PaddingOptions): boolean;
                unpad(input: util.ByteBuffer, options: UnpaddingOptions): boolean;
            }

            interface CFB extends BlockMode {
                afterFinish(output, options)
            }

            interface BlockModeFactory<T> {
                new (options: BlockModeOptions): T;
            }

            var ecb: BlockModeFactory<ECB>;
            var cbc: BlockModeFactory<CBC>;
            var cfb: BlockModeFactory<CFB>;
        }
    }

    module aes {
        function startEncrypting(key, iv, output, mode): Cipher;
        function createEncryptionCipher(key, mode): Cipher;
        function startDecrypting(key, iv, output, mode): Cipher;
        function createDecryptionCipher(key, mode): Cipher;

        interface AlgorithmOptions {
            key: WTF;
            decrypt: boolean;
        }

        class Algorithm {
            constructor(name: string, mode);
            initialize(options: AlgorithmOptions): void;
        }

        function _expandKey(key, decrypt);
        function _updateBlock(w, input, output, decrypt)
    }

    module prng {
        interface RandomCallback {
            (err: Error, bytes: string): void;
        }

        interface PseudoRendomGenerator {
            generate(count: number, callback: RandomCallback)
            generateSync(count: number): string;
        }

        function create(plugin): PseudoRendomGenerator;
    }

    interface Random extends prng.PseudoRendomGenerator {
        getBytes(count: number, callback: prng.RandomCallback): void;
        getBytesSync(count: number): string;
    }

    var random: Random;
}
