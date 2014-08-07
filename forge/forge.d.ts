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

        /**
         * Creates a buffer that stores bytes. A value may be given to put into the buffer that is
         * either a string of bytes or a UTF-16 string that will be encoded using UTF-8 (to do the
         * latter, specify 'utf8' as the encoding).
         * 
         * @param {string=} input    (Optional) the bytes to wrap (as a string) or a UTF-16 string to
         *                           encode as UTF-8.
         * @param {string=} encoding (Optional) (default: 'raw', other: 'utf8').
         *
         * @return {ByteBuffer} The new buffer.
         */
        function createBuffer(input?: string, encoding?: string): ByteBuffer;

        /**
         * Fills a string with a particular value. If you want the string to be a byte string, pass in
         * String.fromCharCode(theByte).
         *
         * @param {string} c the character to fill the string with, use String.fromCharCode to fill the
         *                   string with a byte value.
         * @param {number} n the number of characters of value c to fill with.
         *
         * @return {string} the filled string.
         */
        function fillString(c: string, n: number): string;

        /**
         * Performs a per byte XOR between two byte strings and returns the result as a string of bytes.
         *
         * @param {string} s1 first string of bytes.
         * @param {string} s2 second string of bytes.
         * @param {number} n  the number of bytes to XOR.
         *
         * @return {string} the XOR'd result.
         */
        function xorBytes(s1: string, s2: string, n: number): string;

        /**
         * Converts a hex string into a 'binary' encoded string of bytes.
         *
         * @param {string} hex the hexadecimal string to convert.
         *
         * @return {string} the binary-encoded string of bytes.
         */
        function hexToBytes(hex: string): string;

        /**
         * Converts a 'binary' encoded string of bytes to hex.
         *
         * @param {string} bytes the byte string to convert.
         *
         * @return {string} the string of hexadecimal characters.
         */
        function bytesToHex(bytes: string): string;

        /**
         * Converts an 32-bit integer to 4-big-endian byte string.
         *
         * @param {number} i the integer.
         *
         * @return {string} the byte string.
         */
        function int32ToBytes(i: number): string;

        /**
         * Base64 encodes a 'binary' encoded string of bytes.
         *
         * @param {string} input    the binary encoded string of bytes to base64-encode.
         * @param {number=} maxline (Optional) the maximum number of encoded characters per line to use,
         *                          defaults to none.
         *
         * @return {string} the base64-encoded output.
         */
        function encode64(input: string, maxline?: number): string;

        /**
         * Base64 decodes a string into a 'binary' encoded string of bytes.
         *
         * @param {string} input the base64-encoded input.
         *
         * @return {string} the binary encoded string.
         */
        function decode64(input: string): string;

        /**
         * UTF-8 encodes the given UTF-16 encoded string (a standard JavaScript string). Non-ASCII
         * characters will be encoded as multiple bytes according to UTF-8.
         *
         * @param {string} str the string to encode.
         *
         * @return {string} the UTF-8 encoded string.
         */
        function encodeUtf8(str: string): string;

        /**
         * Decodes a UTF-8 encoded string into a UTF-16 string.
         *
         * @param {string} str the string to decode.
         *
         * @return {string} the UTF-16 encoded string (standard JavaScript string).
         */
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
            [name: string]: modes.BlockModeFactory;
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
        function registerAlgorithm(name: string, algorithm: modes.BlockModeFactory): void;
        function getAlgorithm(name: string): modes.BlockModeFactory;

        module modes {
            interface BlockModeOptions {
                cipher: Cipher;
                blockSize: number;
            }

            interface EncryptionOptions {
                iv: any; // string | number[] | ByteBuffer
            }

            interface BlockMode {
                name: string;
                cipher: Cipher;
                blockSize: number;
                start(options: EncryptionOptions): void;
                encrypt(input: util.ByteBuffer, output: util.ByteBuffer): void;
                decrypt(input: util.ByteBuffer, output: util.ByteBuffer): void;
            }

            interface BlockModeFactory {
                new (options: BlockModeOptions): BlockMode;
            }

            interface BlockModeFactoryT<T> {
                new (options: BlockModeOptions): BlockMode;
            }

            interface ECB {
                pad(input: util.ByteBuffer, options: { }): boolean;
                unpad(input: util.ByteBuffer, options: { overflow: number }): boolean;
            }

            interface CBC {
                pad(input: util.ByteBuffer, options: {}): boolean;
                unpad(input: util.ByteBuffer, options: { overflow: number }): boolean;
            }

            interface CFB {
                afterFinish(output: util.ByteBuffer, options: { overflow: number }): boolean;
            }

            interface OFB {
                afterFinish(output: util.ByteBuffer, options: { overflow: number }): boolean;
            }

            interface CTR {
                afterFinish(output: util.ByteBuffer, options: { overflow: number }): boolean;
            }

            interface GCMEncryptionOptions extends EncryptionOptions {
                additionalData?: string;
                tagLength?: number;
                decrypt?: boolean;
                tag?: string;
            }

            interface GCM {
                tag: util.ByteBuffer;

                start(options: GCMEncryptionOptions): void;
                afterFinish(output: util.ByteBuffer, options: { overflow: number; decrypt?: boolean }): boolean;

                multiply(x: number[], y: number[]): number[];
                pow(x: number[], y: number[]): number[];
                tableMultiply(x: number[]): number[];
                ghash(h: number[], y: number[], x: number[]): number[];
                generateHashTable(h: number[], bits: number): number[];
                generateSubHashTable(mid: number[], bits: number): number[];
            }

            var ecb: BlockModeFactoryT<ECB>;
            var cbc: BlockModeFactoryT<CBC>;
            var cfb: BlockModeFactoryT<CFB>;
            var ofb: BlockModeFactoryT<OFB>;
            var ctr: BlockModeFactoryT<CTR>;
            var gcm: BlockModeFactoryT<GCM>;
        }
    }

    module aes {
        function startEncrypting(key: string, iv: string, output: util.ByteBuffer, mode?: string): Cipher;

        function createEncryptionCipher(key, mode): Cipher;
        function startDecrypting(key, iv, output, mode): Cipher;
        function createDecryptionCipher(key, mode): Cipher;

        interface AlgorithmOptions {
            key: any; // string | number[] | ByteBuffer
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
            generate(count: number, callback: RandomCallback): void;
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
