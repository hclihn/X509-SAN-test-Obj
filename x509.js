/** x509.js
 * ASN.1 DER X509 certificate parsing and manipulation.
 * Adopted from https://github.com/nginx/njs-examples (njs/http/certs/js/x509.js)
 * with bug fixes and enhancements.
 */

const DEBUG = false;

/** 
 * Max number of bits for Number.MAX_SAFE_INTEGER.
 * @const {number}
 */
const MAX_INT_BITS = Math.log2(Number.MAX_SAFE_INTEGER);
/** 
 * Max number of bytes befor exceeding Number.MAX_SAFE_INTEGER.
 * @const {number}
 */
const MAX_INT_BYTES = Math.floor(MAX_INT_BITS/8);
/** 
 * Max remaning number beyond MAX_INT_BYTES for  Number.MAX_SAFE_INTEGER.
 *   i.e., MAX_INT_REM_VAL ==  Number.MAX_SAFE_INTEGER / (2**(MAX_INT_BYTES * 8))
 * @const {number}
 */
const MAX_INT_REM_VAL =  (1 << (MAX_INT_BITS - MAX_INT_BYTES * 8)) - 1;

/**
 * The type representing the X.509 Certificate or its substructure.
 * @typedef {(number|string)[]} CertType
 */

/**
 * Parse ASN.1 DER OID.
 * @param  {Buffer} buf - The DER OID value to be parsed.
 * @return {string} The OID string representation.
 * @throws {Error} If the OID field value is longer than 6 bytes or invalid.
 */
function asn1_parse_oid(buf) {
    var oid = [];
    var sid = 0;
    var cur_octet = buf[0];
    if (cur_octet < 40) {
        oid.push(0);
        oid.push(cur_octet);
    } else if (cur_octet < 80) {
        oid.push(1);
        oid.push(cur_octet - 40);
    } else {
        oid.push(2);
        oid.push(cur_octet - 80);
    }
    for (let n = 1; n < buf.length; n++) {
        cur_octet = buf[n];
        if (cur_octet < 0x80) {
            sid += cur_octet;
            if (sid > Number.MAX_SAFE_INTEGER) {
                throw `Failed to parse OID: SID (${sid}) exceeding Number.MAX_SAFE_INTEGER`;
            }
            // end of the SID field
            oid.push(sid);
            sid = 0;
        } else {
            sid += cur_octet & 0x7f; 
            sid <<= 7;
            if (sid > Number.MAX_SAFE_INTEGER) {
                throw `Failed to parse OID: SID (${sid}) exceeding Number.MAX_SAFE_INTEGER`;
            }
        }
    }
    if (buf[buf.length-1] >= 0x80) {
        throw `Failed to parse OID: last octet in OID buffer has highest bit set`;
    }
    return oid.join('.')
}

/** Parse ASN.1 DER Integer.
 * @param  {Buffer} buf - The DER Integer value to be parsed.
 * @return {[boolean, number|string]} a tuple of [in_hex_rep, value].
 *     If the integer value can be converted, in_hex_rep is false, and value is the converted integer.
 *     If the length is logner than 6 bytes, in_hex_rep is true and value is the hex string representation.
 */
function asn1_parse_integer(buf) {
    if (buf.length > MAX_INT_BYTES) { // may exceed MAX_SAFE_INTEGER, lets return hex
        return [true, asn1_parse_any(buf)];
    }
    var value = 0;
    var is_negative = false;
    var compl_int = 0;
    if (buf[0] & 0x80) {
        is_negative = true;
        value = buf[0] & 0x7f;
        compl_int = 1 << (8 * buf.length - 1);
    } else {
        value = buf[0];
    }
    if (buf.length > 1) {
        for (let n = 1; n < buf.length; n++) {
            value <<= 8;
            value += buf[n];
        }
    }
    return [false, (is_negative)? (value - compl_int) : value];
}

/**
 * Parse ASN.1 DER ASCII string.
 * @param  {Buffer} buf - The DER ASCII string value to be parsed.
 * @return {string} The string value.
 */
function asn1_parse_ascii_string(buf) {
    return buf.toString();
}

/**
 * Parse ASN.1 DER IA5 string.
 * @param  {Buffer} buf - The DER IA5 string value to be parsed.
 * @return {string} The string value.
 * @throws {Error} If the string contains non-IA5 characters.
 */
function asn1_parse_ia5_string(buf) {
    if (is_ia5(buf)) {
        return buf.toString();
    } else {
        throw `Invalid IA5String: ${buf}`;
    }
}

/**
 * Parse ASN.1 DER UTF-8 string.
 * @param  {Buffer} buf - The DER UTF-8 string value to be parsed.
 * @return {string} The string value.
 */
function asn1_parse_utf8_string(buf) {
    return buf.toString('utf8');
}

/**
 * Parse ASN.1 DER BMP string.
 * @param  {Buffer} buf - The DER BMP string value to be parsed.
 * @return {string} The string's hex representation.
 */
function asn1_parse_bmp_string(buf) {
    return asn1_parse_any(buf);
}

/**
 * Parse ASN.1 DER Universal string.
 * @param  {Buffer} buf - The DER Universal string value to be parsed.
 * @return {string} The string's hex representation.
 */
function asn1_parse_universal_string(buf) {
    return asn1_parse_any(buf);
}

/**
 * Parse ASN.1 DER BitString.
 * @param  {Buffer} buf - The DER BitString value to be parsed.
 * @return {Buffer} The buffer containing the parsed value.
 * @throws {Error} If the bit padding value is invalid.
 */
function asn1_parse_bit_string(buf) {
    if (buf[0] == 0) { // no padding
        return buf.slice(1);
    }
    const shift = buf[0];
    if (shift > 7) {
        throw `Invalid shift (${shift}) in BitString`;
    }
    var value = Buffer.allocUnsafe(buf.length - 1);
    var upper_bits = 0;
    const mask = ((1 << shift) - 1) & 0xff;
    // shift string right
    for (let n = 1; n < buf.length; n++) {
         let val = (buf[n] >> shift) | upper_bits;
         upper_bits = (buf[n] & mask) << (8 - shift);
         value[n - 1] = val;
    }
    return value;
}

/**
 * Parse ASN.1 DER OctetString.
 * @param  {Buffer} buf - The DER OctetString value to be parsed.
 * @return {string} The string's hex representation.
 */
function asn1_parse_octet_string(buf) {
    return asn1_parse_any(buf);
}

/**
 * Parse ASN.1 arbitrary DER value.
 * @param  {Buffer} buf - The DER value to be parsed.
 * @return {string} The value's hex representation.
 */
function asn1_parse_any(buf) {
    return buf.toString('hex');
}

/**
 * Check if the buffer is an IA5 string.
 * @param  {Buffer} buf - The buffer to be checked.
 * @return {boolean} True if the buffer is an IA5 string.
 */
function is_ia5(buf) {
    for (let n = 0; n < buf.length; n++) {
        if (buf[n] > 0x7e) {
            return false;
        }
    }
    return true;
}

/**
 * Parse ASN.1 DER's length part.
 * @param  {Buffer} buf - The DER length value to be parsed.
 * @param  {number} pointer - the index where the length part starts in buf.
 * @return {[number, number]} The array of [length, index to the value part].
 * @throws {Error} If the length field value is longer than 6 bytes or invalid.
 */
function asn1_read_length(buf, pointer) {
    const s = buf[pointer];
    var length = 0;
    if (s == 0x80 || s == 0xff) {
        throw `Failed to parse ASN.1 length: indefinite length is not supported`;
    }
    if (s < 0x80) { // length is less than 128
        pointer++;
        return [s, pointer];
    } else {
        let l = s & 0x7f;
        if (l > (MAX_INT_BYTES + 1)) {
            throw `Failed to parse ASN.1 length @${pointer}: length (${l}) exceeds Number.MAX_SAFE_INTEGER`;
        }
        if ((pointer + l) >= buf.length) {
            throw `Failed to parse ASN.1 length @${pointer+l}: buffer size (${buf.length}) reached`;
        }
        for (let n = 0; n < l; n++) {
            length = (length * 256) + buf[++pointer];
            if (n == MAX_INT_BYTES && buf[pointer] > MAX_INT_REM_VAL) {
                throw `Failed to parse ASN.1 length @${pointer}: length (${length}+${buf[pointer]}) exceeds Number.MAX_SAFE_INTEGER`;
            }
        }
        return [length, pointer + 1];
    }
}

/**
 * Format the buffer content to an IPv4 address string.
 * @param  {Buffer} buf - The buffer to be formatted.
 * @return {string} The IPv4 address string.
 * @throws {Error} If the buffer is not a valid IPv4 address.
 */
function format_ipv4(buf) {
    if (buf.length != 4) {
        throw `Invalid IPv4 address: buffer legnth (${buf.length}) is not 4`;
    }
    // IPv4 address
    const intStrs = [];
    for (let i = 0; i < buf.length; i++) {
        intStrs.push(String(buf[i]));
    }
    return intStrs.join('.');   
}

/**
 * Format the buffer content to an IPv6 address string.
 * @param  {Buffer} buf - The buffer to be formatted.
 * @return {string} The IPv6 address string.
 * @throws {Error} If the buffer is not a valid IPv6 address.
 */
function format_ipv6(buf) {
    if (buf.length != 16) {
        throw `Invalid IPv6 address: buffer length (${buf.length}) is not 16`;
    }
    // IPv6 address
    const data = buf.toString('hex');
    const fields = [];
    // group in 4 hex digits with leading 0 removed
    for (let i = 0; i < data.length; i+=4) {
        for (let j = 0; j < 4; j++) {
            if (data.charAt(i+j) != '0') {
                fields.push(data.substr(i+j, 4-j));
                break;
            } else if (j == 3) {
                fields.push('0');
            }
        }
    }
    // find the longest consecutive range of 0s
    let max_range = null, start = -1, end = -1;
    for (let i = 0; i < fields.length; i++) {
        if (fields[i] == '0') {
            if (start == -1) {
                start = i;
            }
        } else if (start >= 0) {
            end = i;
            if (max_range === null || end - start > max_range[0]) {
                max_range = [end - start, start, end];
            }
            start = end = -1;
        }
    }
    // use :: for the longest consecutive range of 0s
    if (max_range !== null && max_range[0] > 1) {
        return fields.slice(0, max_range[1]).join(':') + '::' + 
            fields.slice(max_range[2]).join(':');
    }
    return fields.join(':');
}

function parse_datetime_str(s, time_zone, date_only = false) {
    if (date_only) {
        return new Date(Date.parse(`${s.substr(0, 4)}-${s.substr(4, 2)}-${s.substr(6, 2)}${time_zone}`));
    }
    return new Date(Date.parse(`${s.substr(0, 4)}-${s.substr(4, 2)}-${s.substr(6, 2)}T${s.substr(8, 2)}:${s.substr(10, 2)}:${s.substr(12, 2)}${time_zone}`));
}

function get_tag_name(tag) {
    switch(tag) {
        case 0x00: return 'EndOfContent';
        case 0x01: return 'Boolean';
        case 0x02: return 'Integer';
        case 0x03: return 'BitString';
        case 0x04: return 'OctetString';
        case 0x05: return 'Null';
        case 0x06: return 'ObjectIdentifier'; 
        case 0x07: return 'ObjectDescriptor';
        case 0x08: return 'External';
        case 0x09: return 'Real';	
        case 0x0a: return 'Eumerrated';
        case 0x0b: return 'EmbeddedPDV';	
        case 0x0c: return 'UTF8String';
        case 0x0d: return 'RelativeOID';
        case 0x0e: return 'Time';
        // 0x0f reserved
        case 0x10: return 'Sequence';
        case 0x11: return 'Set';
        case 0x12: return 'NumericString';
        case 0x13: return 'PrintableString';
        case 0x14: return 'T61String';
        case 0x15: return 'VideotexString';
        case 0x16: return 'IA5String';
        case 0x17: return 'UTCTime';
        case 0x18: return 'GeneralizedTime';
        case 0x19: return 'GraphicString';
        case 0x1a: return 'VisibleString';
        case 0x1b: return 'GeneralString';
        case 0x1c: return 'UniversalString';
        case 0x1d: return 'CharacterString';
        case 0x1e: return 'BMPString';
        case 0x1f: return 'Date';
        case 0x20: return 'TimeOfDay';
        case 0x21: return 'DateTime';
        case 0x22: return 'Duration';
        case 0x23: return 'OID-IRI';	
        case 0x24: return 'RelativeOID-IRI';
        default: return `Tag-${tag}`; // just in case
    }
}

function get_class_name(cls) {
    switch(cls) {
        case 0: return 'Universal';
        case 1: return 'Application';
        case 2: return 'Context';
        case 3: return 'Private';
        default: return `Class-${cls}`; // unlikely!
    }
}

function ASNObj(cls, tag, constructed, value, in_hex = false) {
    this.cls = cls;
    this.tag = tag;
    this.type = (cls == 0)? get_tag_name(tag):`${get_class_name(cls)}-${tag}`;        
    this.constructed = constructed;
    this.in_hex = in_hex; // value in hex representation
    this.value = value;
}

/**
 * Parse ASN.1 DER primitive.
 * @param  {number} cls - The DER class.
 * @param  {number} tag - The DER tag.
 * @param  {Buffer} buf - The DER value to be parsed.
 * @return {string|number|CertType} The parsed value.
 */
function asn1_parse_primitive(cls, tag, constructed, buf) {
    if (cls == 0) { // universla class
        switch(tag) {
            case 0x00: //End-of-Content (EOC)
                return new ASNObj(cls, tag, false, null);
            case 0x01: // Boolean
                return new ASNObj(cls, tag, false, buf[0] != 0x00);
            case 0x02: // INTEGER
                const [in_hex, val] = asn1_parse_integer(buf);
                return new ASNObj(cls, tag, false, val, in_hex);
            case 0x03: // BIT STRING
                // get the BitSting value first, then try to see if we can parse
                // the DER substructure. If not, then return the hex representation.
                const data = asn1_parse_bit_string(buf);
                try {
                    return new ASNObj(cls, tag, true, asn1_read(data));
                } catch(e) {
                    return new ASNObj(cls, tag, false, data.toString('hex'), true);
                }
            case 0x04: // OCTET STRING
                // Try to see if we can parse the DER substructure. 
                // If not, then return the hex representation.
                try {
                    return new ASNObj(cls, tag, true, asn1_read(buf));
                } catch(e) {
                    return new ASNObj(cls, tag, false, asn1_parse_octet_string(buf), true);
                }
            case 0x05: // Null
                return new ASNObj(cls, tag, false, null);
            case 0x06: // OBJECT IDENTIFIER
                return new ASNObj(cls, tag, false, asn1_parse_oid(buf));
            case 0x07: // Object Descriptor
                return new ASNObj(cls, tag, false, asn1_parse_ascii_string(buf));
            case 0x08: // EXTERNAL	
            case 0x09: //REAL (float)	
            case 0x0a: //ENUMERATED
            case 0x0b: //EMBEDDED PDV	
                return new ASNObj(cls, tag, false, asn1_parse_any(buf), true);
            case 0x0c: // UTF8String
                return new ASNObj(cls, tag, false, asn1_parse_utf8_string(buf));
            case 0x0d: //Relative-OID
                return new ASNObj(cls, tag, false, asn1_parse_oid(buf));
            // 0x0f reserved
            case 0x10: //Sequence
            case 0x11: // Set
                return new ASNObj(cls, tag, true, asn1_read(buf));
           
            case 0x0e: // TIME
            case 0x12: // NumericString
            case 0x13: // PrintableString
            case 0x14: // T61String
            case 0x15: // VideotexString
                return new ASNObj(cls, tag, false, asn1_parse_ascii_string(buf));
            case 0x16: // IA5String
                return new ASNObj(cls, tag, false, asn1_parse_ia5_string(buf));
            case 0x17: { // UTCTime (YYMMDDHHMMSSZ)
                let s = buf.toString();
                if (s.length != 13) {
                    throw `Invalid UTCTime (${s}): length (${s.length}) is not 13`;
                }
                if (s[0] >= '5') {
                    s = '19' + s;
                } else {
                    s = '20' + s;
                }
                return new ASNObj(cls, tag, false, parse_datetime_str(s.slice(0, -1), s[14]));
            }
            case 0x18: { // GeneralizedTime (YYYYMMDDHHMMSSZ)
                let s = buf.toString();
                if (s.length != 15) {
                    throw `Invalid GeneralizedTime (${s}): length (${s.length}) is not 15`;
                }
                return new ASNObj(cls, tag, false, parse_datetime_str(s.slice(0, -1), s[14]));
            }
            case 0x19: // GraphicString
            case 0x1a: // VisibleString
            case 0x1b: // GeneralString
                return new ASNObj(cls, tag, false, asn1_parse_ascii_string(buf));
            
            case 0x1c: // UniversalString
                return new ASNObj(cls, tag, false, asn1_parse_universal_string(buf));
            
            case 0x1d: // CHARACTER STRING
                return new ASNObj(cls, tag, false, asn1_parse_ascii_string(buf));
            case 0x1e: // BMPString
                return new ASNObj(cls, tag, false, asn1_parse_bmp_string(buf));
            
            case 0x1f: // DATE (YYYYMMDD)
            case 0x20: // TIME-OF-DAY
            case 0x21: // DATE-TIME (YYYYMMDDHHMMSS)
            case 0x22: // DURATION
            case 0x23: // OID-IRI	
            case 0x24: // RELATIVE-OID-IRI
                return new ASNObj(cls, tag, false, asn1_parse_ascii_string(buf));
            default: 
                return new ASNObj(cls, tag, false, asn1_parse_any(buf), true);
        }
    } else { // other classes
        if (constructed) {
            return new ASNObj(cls, tag, true, asn1_read(buf));
        } else {
            return new ASNObj(cls, tag, false, buf.toString('hex'), true);
        }
    }
}

/**
 * Parse ASN.1 DER buffer.
 * @param  {Buffer} buf - The DER buffer to be parsed.
 * @return {CertType} The parsed object stored in multi-level array of strings or numbers.
 * @throws {Error} If the buffer is not a valid DER.
 */
function asn1_read(buf) {
    var a = [];
    var tag_class;
    var tag;
    var pointer = 0;
    var is_constructed;
    var s = '';
    var length;
    while (pointer < buf.length) {
        // read type: 7 & 8 bits define class, 6 bit if it is constructed
        s = buf[pointer];
        tag_class = s >> 6;
        is_constructed = (s & 0x20) != 0;
        tag = s & 0x1f;
        if (tag == 0x1f) {
            tag = 0;
            let i = 0;
            do {
                if (i > 3) {
                    throw `Failed to parse ASN.1 tag @${pointer}: invalid tag value: ${tag}`;
                }
                i++;
                if (++pointer >= buf.length) {
                    throw `Failed to parse ASN.1 tag @${pointer}: buffer length (${buf.length}) reached`;
                }
                tag <<= 7;
                tag += (buf[pointer] & 0x7f);
            } while (buf[pointer] > 0x80);
        }
        if (++pointer > buf.length) {
             throw `Failed to parse ASN.1 length @${pointer}: buffer length (${buf.length}) reached`;
        }
        var [length, pointer] = asn1_read_length(buf, pointer);
        if ((pointer + length) > buf.length) {
             throw `Failed to parse ASN.1 length @${pointer}: length (${length}) exceeds buffer size (${buf.length})`;
        }
        if (DEBUG) {
            if (is_constructed) {
                console.log('constructed', tag_class, tag.toString(16), length.toString(16), pointer.toString(16))
            } else {
                console.log('primitive  ', tag_class, tag.toString(16), length.toString(16), pointer.toString(16))
            }
        }
        a.push(asn1_parse_primitive(tag_class, tag,is_constructed, buf.slice(pointer, pointer + length)));
        pointer += length;
    }
    return a;
}

function process_san(asn_obj) {
    if (asn_obj.cls == 2) { // context specific, non-constructed
        /* SAN GeneralName ::= CHOICE {
            otherName                       [0]     OtherName,
            rfc822Name                      [1]     IA5String,
            dNSName                         [2]     IA5String,
            x400Address                     [3]     ORAddress,
            directoryName                   [4]     Name,
            ediPartyName                    [5]     EDIPartyName,
            uniformResourceIdentifier       [6]     IA5String,
            iPAddress                       [7]     OCTET STRING,
            registeredID                    [8]     OBJECT IDENTIFIER 
        }*/
        const buf = Buffer.from(asn_obj.value, 'hex');
        switch(asn_obj.tag) {
            case 0x00: 
                asn_obj.value = asn1_parse_any(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'otherName';
                return;
            case 0x01: 
                asn_obj.value =  asn1_parse_ascii_string(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'rfc822Name';
                return;
            case 0x02:
                asn_obj.value = asn1_parse_ascii_string(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'dNSName';
                return;
            case 0x03: 
                asn_obj.value = asn1_parse_any(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'x400Address';
                return;
            case 0x04: 
                asn_obj.value = asn1_parse_any(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'directoryName';
                return;
            case 0x05: 
                asn_obj.value = asn1_parse_any(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'ediPartyName';
                return;
            case 0x06: 
                asn_obj.value = asn1_parse_ascii_string(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'uniformResourceIdentifier';
                return;
            case 0x07: 
                if (buf.length == 4) { // IPv4 address
                    asn_obj.value = format_ipv4(buf);   
                    asn_obj.in_hex = false;
                    asn_obj.subtype = 'iPAddressV4';
                    return;
                } else if (buf.length == 16) { // IPv6 address
                    asn_obj.value =  format_ipv6(buf);
                    asn_obj.in_hex = false;
                    asn_obj.subtype = 'iPAddressV6';
                    return;
                }
                // unlikely, unless we have a new IP address type
                asn_obj.value = asn1_parse_any(buf);
                asn_obj.in_hex = true;
                asn_obj.subtype = 'iPAddress';
                return;
            case 0x08: 
                asn_obj.value = asn1_parse_any(buf);
                asn_obj.in_hex = false;
                asn_obj.subtype = 'registeredID';
                return;
            default: // just in case
                asn_obj.value =asn1_parse_any(buf);
                asn_obj.in_hex = true;
                asn_obj.subtype = 'unknown';
                return;
        }
    }
}

// Path element spec: name_spac[index_spec]
// name_spac = {alphabet | digit | hyphen}[{alphabet | digit | hyphen}...]
// index_spec = '[' + {digits|*} + ']'
const PATH_SPEC = /^(?<name>[a-z0-9-]+)(?:\[(?<idx>(?:[0-9]+|[*]))\])?$/i;

function travers_ASN(obj, path, level = 0) {
    if (path.length == level) {
        if (obj.constructor.name == 'ASNObj') {
            return [{'path': [obj.type], 'obj': obj}];
        }
        return [{'path': [':value:'], 'obj': obj}];
    }
    const p = path[level];
    const m = p.match(PATH_SPEC);
    if (m === null) {
        throw `Invalid path element[${level}]: ${p}`;
    }
    if (obj.type != m.groups.name) {
        throw `Path element[${level}] (${p}) does not match ${obj.type}`;
    }
    if (m.groups.idx === undefined) { // no [...] part
        if (Array.isArray(obj.value)) {
            throw `Missing index spec: path element[${level}] (${p}) value is an array`;
        }
        const a = travers_ASN(obj.value, path, level + 1);
        for (let i = 0; i < a.length; i++) {
            a[i].path.unshift(`${obj.type}`);
        }
        return a;
    } else if (!Array.isArray(obj.value)) {
        throw `Invalid index spec ([${m.groups.idx}]): path element[${level}] (${p}) value is not an array`
    }
    if (m.groups.idx == '*') { // the [*] case
        const a = [];
        for (let i = 0; i < obj.value.length; i++) {
            try {
                const ar =  travers_ASN(obj.value[i], path, level + 1);
                for (let j = 0; j < ar.length; j++) {
                    ar[j].path.unshift(`${obj.type}[${i}]`);
                }
                a.push(...ar);
            } catch(e) { // no match for this array element, try next
                continue;
            }
        }
        if (a.length == 0) {
            throw `No match found for path element[${level}] (${p})`;
        }
        return a;
    }
    // the [idx] case
    const idx = parseInt(m.groups.idx, 10);
    if (Number.isNaN(idx)) { // unlikely due to regexp
        throw `Invalid index spec ([${m.groups.idx}]): path element[${level}] (${p})`;
    } else if (idx < 0 || idx >= obj.value.length) {
        throw `Invalid index spec: path element[${level}] (${p}) index (${idx}) out of range of [0...${obj.value.length - 1}]`;
    }
    const a = travers_ASN(obj.value[idx], path, level + 1);
    for (let i = 0; i < a.length; i++) {
        a[i].path.unshift(`${obj.type}[${idx}]`);
    }
    return a;
}

const CERT_VER_PATH = [
    'Sequence[0]' /* TBSCertificate */, 
    'Sequence[0]' /* Version */, 'Context-0[0]', "Integer"];

function get_cert_version(cert) {
    const a = travers_ASN(cert, CERT_VER_PATH);
    if (a.length != 1) {
        throw `Failed to find version in certificate`;
    }
    return a[0].obj;
}

const CERT_VALID_PATH = [
    'Sequence[0]' /* TBSCertificate */, 
    'Sequence[4]' /* Validity */, 'Sequence[*]'];

function get_cert_validity(cert) {
    const a = travers_ASN(cert, CERT_VALID_PATH);
    if (a.length != 2) {
        throw `Failed to find validity in certificate`;
    }
    return {'notBefore': a[0].obj.value, 'notAfter': a[1].obj.value};
}

const SAN_PATH = [
    'Sequence[0]' /* TBSCertificate */, 
    'Sequence[*]', 'Context-3[0]' /* Extensions */, 'Sequence[*]', 
    /* Extension */ 'Sequence[0]', 'ObjectIdentifier'];

function get_SAN_value(cert) {
    const vals = travers_ASN(cert, SAN_PATH);
    var obj = null;
    for (let i = 0; i < vals.length; i++) {
        // subjectAltName OID is 2.5.29.17
        if (vals[i].obj == "2.5.29.17") {
            obj = vals[i];
            break;
        }
    }
    if (obj === null) {
        throw `Invalid PEM certificate: missing subjectAltName (OID 2.5.29.17)`;
    }
    // Replace last 3 pathe elements ('Sequence[0]', 'Object-Identifier', ':value:')
    // with 'Sequence[1]', 'Octet-String[0]', 'Sequence[*]' to get SAN values.
    const ps = travers_ASN(cert, obj.path.slice(0, -3).concat([
        'Sequence[1]', 'OctetString[0]', 'Sequence[*]']));
    return ps;
}

function parse_cert(der_str) {
    const cert = asn1_read(Buffer.from(der_str, 'base64'));
    if (cert.length != 1) {
        throw `Invalid X.509 certificate: got ${cert.length} elements, expected 1`;
    }
    const vals = get_SAN_value(cert[0]);
    for (let i = 0; i < vals.length; i++) {
        process_san(vals[i].obj)
    }
    return cert[0];
}

/**
 * Parse one or more X.509 certificates in PEM format.
 * @param  {string} pem - The PEM string to be parsed.
 * @return {CertType} The parsed certificate in a multi-level array.
 *   Values are in strings or numbers.
 * @throws {Error} If the PEM string is not a valid X.509 certificate.
 */
function parse_pem_certs(pem) {
    const der = pem.split(/\n/);
    const certs = [];
    if (pem.match(' CERTIFICATE-')) {
        var start = -1, end = -1;
        for (let i = 0; i < der.length; i++) {
            if (der[i].match('-----BEGIN CERTIFICATE-----')) {
                start = i+1;
            } else if (der[i].match('-----END CERTIFICATE-----')) {
                end = i;
                if (start < 0 || end <= start) {
                    throw `Invalid PEM certificate: failed to locate start and/or end of certificate`;
                }
                const der_str = der.slice(start, end).join('');
                certs.push(parse_cert(der_str));
                // next cert
                start = -1;
                end = -1;
            }
        }
    } else {
        throw `Invalid PEM certificate: missing PEM 'CERTIFICATE' lines`;
    }
    return certs;
}

/**
 * Get subjectAltName (SAN) from X.509 PEM certificate.
 * @param  {string} pem_cert - The PEM string to be parsed.
 * @return {string[]} The array of SANs.
 * @throws {Error} If pem_cert is empty.
 */
function get_san(pem_cert, index = 0, check_validity = true) {
    if (!pem_cert) {
        throw 'Empty client PEM certificate string specified';
    }
    if (index < 0) {
        throw `Invalid index (${index}) specified`;
    }
    const certs = parse_pem_certs(pem_cert);
    if (index >= certs.length) {
        throw 'Index (${index}) out of range of [0...${certs.length - 1}]';
    }
    const cert = certs[index];
    if (DEBUG) {
        console.log(JSON.stringify(cert, null, 2));
    }
    const v = get_cert_version(cert);
    if (v != 2) {
        throw `Invalid certificate version for subjectAltName: ${v}`;
    }
    const validity = get_cert_validity(cert);
    const now = new Date();
    if (check_validity && (validity.notBefore > now || validity.notAfter < now)) {
        throw `Invalid certificate validity: ${validity.notBefore} to ${validity.notAfter}`;
    }
    const info = get_SAN_value(cert)
    const  sans = [];
    for (let i = 1; i < info.length; i++) {
        sans.push(info[i].obj.value);
    }
    return sans;
}

/**
 * Converts HTTP header value to the PEM string.
 * @param  {string} header - The HTTP header value containing the certificate.
 * @return {string} The PEM certificate string.
 */
function header2pem(header) {
    var pem = header.replace(/(BEGIN|END) (CERT)/g, '\$1#\$2');
    pem = pem.replace(/ /g, '\n').replace(/#/g, ' ');
    if (pem[-1] != '\n') {
        pem += '\n'
    }
    return pem;
}

export default {asn1_read, parse_pem_certs, get_san, header2pem};

    