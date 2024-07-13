/** x509.js
 * ASN.1 DER X.509 certificate parsing and accessing.
 * Uses the object to represent the ASN.1 structure for easy structural validation and access.
 * Though this library fully decode the ASN.1 DER structure, it only processes parts of the X.509 certificate objects
 * like version, validity, and subjectAltName.
 * Processing of other parts of the certificate can be done by traverse_ASN() on ASNObj.
 *
 * Reference: https://datatracker.ietf.org/doc/html/rfc5280#page-16
 * Rewriting from https://github.com/nginx/njs-examples (njs/http/certs/js/x509.js) with bug fixes and lot of
 * enhancements.
 *
 * Nginx njs does not support the following Javascript features:
 *  1. Default values for function parameters, e.g., function f(a, b = 1) {...}.
 *  2. Destructuring assignment, e.g., [x, y] = test().
 *  3. Spread (...) syntax, e.g., a.push(...b).
 */

/** Show debug messages in console?
 * @const {boolean}
 */
const DEBUG = true;
/** Max number of bits for Number.MAX_SAFE_INTEGER.
 * @const {number}
 */
const MAX_INT_BITS = Math.log2(Number.MAX_SAFE_INTEGER);
/** Max number of bytes before exceeding Number.MAX_SAFE_INTEGER.
 * @const {number}
 */
const MAX_INT_BYTES = Math.floor(MAX_INT_BITS/8);
/** Max remaning number beyond MAX_INT_BYTES for  Number.MAX_SAFE_INTEGER.
 *   i.e., MAX_INT_REM_VAL ==  Number.MAX_SAFE_INTEGER / (2**(MAX_INT_BYTES * 8))
 * @const {number}
 */
const MAX_INT_REM_VAL =  (1 << (MAX_INT_BITS - MAX_INT_BYTES * 8)) - 1;

/** Parse ASN.1 DER OID.
 * @param  {Buffer} buf - The DER OID value to be parsed.
 * @return {string} The OID string representation.
 * @throws {Error} If the OID field value is longer than 6 bytes or invalid.
 */
function asn1_parse_oid(buf) {
    /** @type {string[]} */
    var oid = [];
    var cur_octet = buf[0];
    if (cur_octet < 40) {
        oid.push(0, cur_octet);
    } else if (cur_octet < 80) {
        oid.push(1, cur_octet - 40);
    } else {
        oid.push(2, cur_octet - 80);
    }
    for (let n = 1, sid = 0; n < buf.length; n++) {
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
    return oid.join('.');
}

/** Parse ASN.1 DER Integer.
 * @param  {Buffer} buf - The DER Integer value to be parsed.
 * @return {[boolean, (number|string)]} a tuple of [in_hex_rep, value].
 *   If the integer value can be converted, in_hex_rep is false, and value is the converted integer.
 *   If the length is longer than 6 bytes, in_hex_rep is true and value is the hex string representation.
 */
function asn1_parse_integer(buf) {
    if (buf.length > MAX_INT_BYTES) { // may exceed MAX_SAFE_INTEGER, lets return hex
        return [true, asn1_parse_any(buf)];
    }
    var value = 0, is_negative = false, compliment_int = 0;
    if (buf[0] & 0x80) {
        is_negative = true;
        value = buf[0] & 0x7f;
        compliment_int = 1 << (8 * buf.length - 1);
    } else {
        value = buf[0];
    }
    if (buf.length > 1) {
        for (let n = 1; n < buf.length; n++) {
            value = (value << 8) + buf[n];
        }
    }
    return [false, (is_negative)? (value - compliment_int) : value];
}

/** Parse ASN.1 DER ASCII string types.
 * @param  {Buffer} buf - The DER ASCII string value to be parsed.
 * @return {string} The string value.
 */
function asn1_parse_ascii_string(buf) {
    return buf.toString();
}

/** Check if the buffer is an IA5 string.
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

/** Parse ASN.1 DER IA5 string.
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

/** Parse ASN.1 DER UTF-8 string.
 * @param  {Buffer} buf - The DER UTF-8 string value to be parsed.
 * @return {string} The string value.
 */
function asn1_parse_utf8_string(buf) {
    return buf.toString('utf8');
}

/** Parse ASN.1 DER BMP string.
 * @param  {Buffer} buf - The DER BMP string value to be parsed.
 * @return {string} The string's hex representation.
 * @throws {Error} If the string is not a BMP string.
 */
function asn1_parse_bmp_string(buf) {
    // BMP string is a sequence of UTF-16BE encoded code points.
    var l = buf.length;
    if (l % 2 != 0) {
        throw `Invalid BMPString: length is not even`;
    } else if (buf[l-1] == 0 && buf[l-2] == 0) { // remove terminators
        l -= 2;
    }
    // Javascript only support utf16le decoding, so we need to convert utf-16be to utf16le.
    const value = Buffer.allocUnsafe(l);
    for (let i = 0; i < l; i+=2) {
        value[i] = buf[i+1];
        value[i+1] = buf[i];
    }
    return value.toString('utf16le');
}

/** Parse ASN.1 DER Universal string.
 * @param  {Buffer} buf - The DER Universal string value to be parsed.
 * @return {string} The string's hex representation.
 */
function asn1_parse_universal_string(buf) {
    return asn1_parse_any(buf);
}

/** Parse ASN.1 DER BitString.
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
    const value = Buffer.allocUnsafe(buf.length - 1);
    var upper_bits = 0;
    const mask = ((1 << shift) - 1) & 0xff;
    // shift bits right shift bits
    for (let n = 1; n < buf.length; n++) {
         let val = (buf[n] >> shift) | upper_bits;
         upper_bits = (buf[n] & mask) << (8 - shift);
         value[n - 1] = val;
    }
    return value;
}

/** Parse ASN.1 DER OctetString.
 * @param  {Buffer} buf - The DER OctetString value to be parsed.
 * @return {string} The string's hex representation.
 */
function asn1_parse_octet_string(buf) {
    return asn1_parse_any(buf);
}

/** Parse ASN.1 arbitrary DER value.
 * @param  {Buffer} buf - The DER value to be parsed.
 * @return {string} The value's hex representation.
 */
function asn1_parse_any(buf) {
    return buf.toString('hex');
}

/** Convert ASN.1 DER GeneralizedTime style string to Date.
 * @param  {string} s - The date-time string (YYYYMMDDhhmmss) to be converted.
 * @param  {string} time_zone - The string of the timezone code (e.g., 'Z').
 * @param  {boolean} date_only - Indicates if s only contains the date part.
 * @return {Date} The Date object.
 * @throws {Error} If the date-time and/or time_zone string is invalid.
 */
function parse_datetime_str(s, time_zone, date_only) {
    var ts = `${s.substr(0, 4)}-${s.substr(4, 2)}-${s.substr(6, 2)}`;
    if (!date_only) {
        ts += `T${s.substr(8, 2)}:${s.substr(10, 2)}:${s.substr(12, 2)}`;
    }
    if (time_zone.length > 0) {
        ts += `${time_zone}`;
    }
    const t = Date.parse(ts);
    if (isNaN(t)) {
        throw `Invalid date-time (${s}) and/or timezone (${time_zone}) string`;
    }
    return new Date(t);
}

/** Parse ASN.1 DER's length part.
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
            length = (length << 8) + buf[++pointer];
            if (n == MAX_INT_BYTES && buf[pointer] > MAX_INT_REM_VAL) {
                throw `Failed to parse ASN.1 length @${pointer}: length (${length}+${buf[pointer]}) exceeds `+
                    `Number.MAX_SAFE_INTEGER`;
            }
        }
        return [length, pointer + 1];
    }
}

/** Get the ASN.1 DER Universal class tag name.
 * @param  {number} tag - The ASN.1 DER tag.
 * @return {string} The tag name.
 */
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
        case 0x0a: return 'Enumerated';
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

/** Get the ASN.1 DER class name.
 * @param  {number} tag_class - The ASN.1 DER class.
 * @return {string} The class name.
 */
function get_class_name(tag_class) {
    switch(tag_class) {
        case 0: return 'Universal';
        case 1: return 'Application';
        case 2: return 'Context';
        case 3: return 'Private';
        default: return `Class-${tag_class}`; // unlikely!
    }
}

// Nginx njs only supports function constructors, not ES6 classes!

/** ASN.1 Object.
 * @class ASNObj
 * @property {number} tag_class - ASN.1 class.
 * @property {number} tag - The ASN.1 tag.
 * @property {string} type - The type string constructed from tag_class and tag.
 * @property {string?} subtype - The subtype constructed from context.
 * @property {Boolean} constructed - Indicates if the The ASN.1 DER tag is constructed.
 * @property {(number|string|Date|ASNObj[])} value - The ASN.1 objects' value.
 * @property {boolean} in_hex - Indicates if the value is a hex string.
 * @constructor ASN.1 object constructor.
 * @param  {number} tag_class - The ASN.1 object's class.
 * @param  {number} tag - The ASN.1 object's tag.
 * @param  {Boolean} constructed - Indicates if the The ASN.1 DER tag is constructed.
 * @param  {(number|string|Date|ASNObj[])} value - The ASN.1 objects' value.
 * @param  {boolean} in_hex - Indicates if the value is a hex string.
 * @return {ASNObj} The ASN.1 object.
 */
function ASNObj(tag_class, tag, constructed, value, in_hex) {
    this.tag_class = tag_class;
    this.tag = tag;
    this.type = (tag_class == 0)? get_tag_name(tag) : `${get_class_name(tag_class)}-${tag}`;
    this.constructed = constructed;
    this.in_hex = in_hex; // value in hex string representation?
    this.value = value;
}

/** Parse ASN.1 DER primitive.
 * @param  {number} tag_class - The DER class.
 * @param  {number} tag - The DER tag.
 * @param  {Boolean} constructed - Indicates if the The DER tag is constructed.
 * @param  {Buffer} buf - The DER value to be parsed.
 * @return {ASNObj|ASNObj[]} The ASN.1 object(s) for the parsed content.
 * @throws {Error} If the DER value is invalid.
 */
function asn1_parse_primitive(tag_class, tag, constructed, buf) {
    if (tag_class == 0) { // Universal class
        switch(tag) {
            case 0x00: //End-of-Content
                return new ASNObj(tag_class, tag, false, null, false);
            case 0x01: // Boolean
                return new ASNObj(tag_class, tag, false, buf[0] != 0x00, false);
            case 0x02: { // INTEGER
                const p = asn1_parse_integer(buf);
                return new ASNObj(tag_class, tag, false, p[1], p[0]);
            }
            case 0x03: { // BIT STRING
                // get the BitSting value first, then try to see if we can parse
                // the DER substructure. If not, then return the hex representation.
                const data = asn1_parse_bit_string(buf);
                try {
                    return new ASNObj(tag_class, tag, true, asn1_read(data), false);
                } catch(e) {
                    return new ASNObj(tag_class, tag, false, data.toString('hex'), true);
                }
            }
            case 0x04: // OCTET STRING
                // Try to see if we can parse the DER substructure.
                // If not, then return the hex representation.
                try {
                    return new ASNObj(tag_class, tag, true, asn1_read(buf), false);
                } catch(e) {
                    return new ASNObj(tag_class, tag, false, asn1_parse_octet_string(buf), true);
                }
            case 0x05: // Null
                return new ASNObj(tag_class, tag, false, null, false);
            case 0x06: // OBJECT IDENTIFIER
                return new ASNObj(tag_class, tag, false, asn1_parse_oid(buf), false);
            case 0x07: // Object Descriptor
                return new ASNObj(tag_class, tag, false, asn1_parse_ascii_string(buf), false);
            case 0x08: // EXTERNAL
            case 0x09: //REAL (float)
            case 0x0a: //ENUMERATED
            case 0x0b: //EMBEDDED PDV
                return new ASNObj(tag_class, tag, false, asn1_parse_any(buf), true);
            case 0x0c: // UTF8String
                return new ASNObj(tag_class, tag, false, asn1_parse_utf8_string(buf), false);
            case 0x0d: //Relative-OID
                return new ASNObj(tag_class, tag, false, asn1_parse_oid(buf), false);
            case 0x0f: // reserved
                throw `Failed to parse ASN.1 primitive: tag (${tag}) is reserved`;
            case 0x10: //Sequence
            case 0x11: // Set
                return new ASNObj(tag_class, tag, true, asn1_read(buf), false);
            case 0x0e: // TIME
            case 0x12: // NumericString (0-9 ans SP)
            case 0x13: // PrintableString (A-Z, a-z, 0-9, '-), +-/, SP, :, =, ?, *, &)
            case 0x14: // T61String
            case 0x15: // VideotexString
                return new ASNObj(tag_class, tag, false, asn1_parse_ascii_string(buf), false);
            case 0x16: // IA5String
                return new ASNObj(tag_class, tag, false, asn1_parse_ia5_string(buf), false);
            case 0x17: { // UTCTime (YYMMDDHHMMSSZ)
                let s = buf.toString();
                if (s.length != 13) {
                    throw `Invalid UTCTime (${s}): length (${s.length}) is not 13`;
                }
                // add the centry part of the year
                s = (s[0] >= '5'? '19': '20') + s;
                return new ASNObj(tag_class, tag, false, parse_datetime_str(s.slice(0, -1), s[14], false));
            }
            case 0x18: { // GeneralizedTime (YYYYMMDDHHMMSSZ)
                let s = buf.toString();
                if (s.length != 15) {
                    throw `Invalid GeneralizedTime (${s}): length (${s.length}) is not 15`;
                }
                return new ASNObj(tag_class, tag, false, parse_datetime_str(s.slice(0, -1), s[14], false));
            }
            case 0x19: // GraphicString
            case 0x1a: // VisibleString (0x20-0x7f)
            case 0x1b: // GeneralString
                return new ASNObj(tag_class, tag, false, asn1_parse_ascii_string(buf), false);
            case 0x1c: // UniversalString
                return new ASNObj(tag_class, tag, false, asn1_parse_universal_string(buf), false);
            case 0x1d: // CHARACTER STRING
                return new ASNObj(tag_class, tag, false, asn1_parse_ascii_string(buf), false);
            case 0x1e: // BMPString
                return new ASNObj(tag_class, tag, false, asn1_parse_bmp_string(buf), false);
            case 0x1f: // DATE (YYYYMMDD)
            case 0x20: // TIME-OF-DAY
            case 0x21: // DATE-TIME (YYYYMMDDHHMMSS)
            case 0x22: // DURATION
            case 0x23: // OID-IRI
            case 0x24: // RELATIVE-OID-IRI
                return new ASNObj(tag_class, tag, false, asn1_parse_ascii_string(buf), false);
            default:
                return new ASNObj(tag_class, tag, false, asn1_parse_any(buf), true);
        }
    } else { // other classes
        if (constructed) {
            return new ASNObj(tag_class, tag, true, asn1_read(buf), false);
        } else {
            return new ASNObj(tag_class, tag, false, buf.toString('hex'), true);
        }
    }
}

/** Parse ASN.1 DER buffer.
 * @param  {Buffer} buf - The DER buffer to be parsed.
 * @return {ASNObj[]} The parsed object(s) stored in an array.
 * @throws {Error} If the buffer is not a valid DER.
 */
function asn1_read(buf) {
    /** @type {ASNObj[]} */
    const a = [];
    var pointer = 0, length = 0;
    while (pointer < buf.length) {
        // read type: 7 & 8 bits define class, 6 bit if it is constructed
        const s = buf[pointer];
        const tag_class = s >> 6;
        const is_constructed = (s & 0x20) != 0;
        let tag = s & 0x1f;
        if (tag == 0x1f) { // a multi-byte tag
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
                tag = (tag << 7) + (buf[pointer] & 0x7f);
            } while (buf[pointer] > 0x80);
        }
        if (++pointer > buf.length) {
            throw `Failed to parse ASN.1 length @${pointer}: buffer length (${buf.length}) reached`;
        }
        const p = asn1_read_length(buf, pointer);
        length = p[0], pointer = p[1];
        if ((pointer + length) > buf.length) {
            throw `Failed to parse ASN.1 length @${pointer}: length (${length}) exceeds buffer size (${buf.length})`;
        }
        if (DEBUG) {
            if (is_constructed) {
                console.log('constructed', tag_class, tag.toString(16), length.toString(16), pointer.toString(16));
            } else {
                console.log('primitive  ', tag_class, tag.toString(16), length.toString(16), pointer.toString(16));
            }
        }
        a.push(asn1_parse_primitive(tag_class, tag,is_constructed, buf.slice(pointer, pointer + length)));
        pointer += length;
    }
    return a;
}

/** Format the buffer content to an IPv4 address string.
 * @param  {Buffer} buf - The buffer to be formatted.
 * @return {string} The IPv4 address string.
 * @throws {Error} If the buffer is not a valid IPv4 address.
 */
function format_ipv4(buf) {
    if (buf.length != 4) {
        throw `Invalid IPv4 address: buffer legnth (${buf.length}) is not 4`;
    }
    // IPv4 address
    /** @type {string[]} */
    const fields = [];
    for (let i = 0; i < buf.length; i++) {
        fields.push(String(buf[i]));
    }
    return fields.join('.');
}

/** Format the buffer content to an IPv6 address string.
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
    /** @type {string[]} */
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
    /** Array of [length, start, end].
     * @type {number[]|null} */
    let max_range = null;
    let start = -1, end = -1;
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
        return fields.slice(0, max_range[1]).join(':') + '::' + fields.slice(max_range[2]).join(':');
    }
    return fields.join(':');
}

/** Process the subjectAltName (SAN) extension in the certificate.
 * @param  {ASNObj} asn_obj - The root ASN.1 object of the certificate. Each SAN entry is updated in place with the
 *   subtype property added to indicated the entry's content type (e.g., dNSName).
 */
function process_san(asn_obj) {
    if (asn_obj.tag_class == 2) { // context specific, non-constructed
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
        const buf = Buffer.from(asn_obj.value, 'hex'); // convert hex value back to Buffer to process.
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

/** Path element spec: name_spec[index_spec].
 * name_spec = {alphabet|digit|hyphen}[{alphabet|digit|hyphen}...].
 * index_spec = '[' + {digits|\*|?} + ']'.
 *    [index]: find match at the known index.
 *    [?]: find only 1 match.
 *    [*]: find 1 or more matches.
 * @typedef {string} PathElementSpec
 */

/** The search result from ASN.1 tree traversing.
 * @typedef  {Object} SearchResult
 * @property {PathElementSpec[]} path - The path of the found object with '*' and '?' replaced with the actual index.
 * @property {(string|number|Date|ASNObj[])} obj - The value of the found object.
 */

/** Regular expression for the path element spec.
 * @const {RegExp}
 */
const PATH_SPEC = /^(?<name>[a-z0-9-]+)(?:\[(?<idx>(?:[0-9]+|[*?]))\])?$/i;

/** Traverse the certificate ASN.1 object tree to find element(s) matching the path.
 * @param  {ASNObj} obj - The ASN.1 object to traverse.
 * @param  {PathElementSpec[]} path - The path element spec array defining the search path.
 * @param  {(string|number|Date)} exp - The expected ASN.1 object value to match at the last level.
 *   Use null if nothing to be expected.
 * @param  {number} level - The traversing level (corresponding to the index of the path array) used by the
 *   recursion.
 * @return {SearchResult[]} The search result(s).
 * @throws {Error} If the path is invalid; or it fails to find the ASNObj tree.
 */
function traverse_ASN(obj, path, exp, level) {
    if (path.length == level) {
        if (exp !== null && exp != obj) {
            throw `Failed to match path element[${level}] (${p}): mismatch value (${obj.value}) with expected (${exp})`;
        }
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
        const a = traverse_ASN(obj.value, path, exp, level + 1);
        for (let i = 0; i < a.length; i++) {
            a[i].path.unshift(`${obj.type}`);
        }
        return a;
    } else if (!Array.isArray(obj.value)) {
        throw `Invalid index spec ([${m.groups.idx}]): path element[${level}] (${p}) value is not an array`;
    }
    if (m.groups.idx == '*' || m.groups.idx == '?') { // the [*|?] case
        // ?: only 1 match
        // *: 1 or more matches
        /** @type {SearchResult[]} */
        const a = [];
        var matches = 0;
        for (let i = 0; i < obj.value.length; i++) {
            try {
                const ar = traverse_ASN(obj.value[i], path, exp, level + 1);
                for (let j = 0; j < ar.length; j++) {
                    ar[j].path.unshift(`${obj.type}[${i}]`);
                    a.push(ar[j]);
                }
                matches++; // tracks matches at this level only
            } catch(e) { // no match for this array element, try next
                continue;
            }
        }
        if (matches == 0) {
            throw `No match found for path element[${level}] (${p})`;
        } else if (matches > 1 && m.groups.idx == '?') {
            throw `Multiple matches (${matches}) found for path element[${level}] (${p})`;
        }
        return a;
    }
    // the [index] case
    const idx = parseInt(m.groups.idx, 10);
    if (isNaN(idx)) { // unlikely due to regexp
        throw `Invalid index spec ([${m.groups.idx}]): path element[${level}] (${p})`;
    } else if (idx < 0 || idx >= obj.value.length) {
        throw `Invalid index spec: path element[${level}] (${p}) index (${idx}) out of range of `+
            `[0...${obj.value.length - 1}]`;
    }
    const a = traverse_ASN(obj.value[idx], path, exp, level + 1);
    for (let i = 0; i < a.length; i++) {
        a[i].path.unshift(`${obj.type}[${idx}]`);
    }
    return a;
}

/** Path element array for the X.509 certificate version.
 * @const {PathElementSpec[]}}
 */
const CERT_VERSION_PATH = ['Sequence[0]' /* TBSCertificate */,
    'Sequence[0]' /* Version */, 'Context-0[0]', "Integer"];

/** Get the X.509 certificate version.
 * @param  {ASNObj} cert - The top-level ASN.1 object representing the certificate.
 * @return {number} The certificate version.
 * @throws {Error} If the number of found version is not 1.
 */
function get_cert_version(cert) {
    const a = traverse_ASN(cert, CERT_VERSION_PATH, null, 0);
    if (a.length != 1) {
        throw `Failed to find version in certificate`;
    }
    return a[0].obj;
}

/** Path element array for the X.509 certificate validity field.
 * @const {PathElementSpec[]}
 */
const CERT_VALID_PATH = ['Sequence[0]' /* TBSCertificate */,
    'Sequence[4]' /* Validity */, 'Sequence[*]'];

/** X.509 certificate validity dates.
 * @typedef  {Object} CertValidity
 * @property {Date} notBefore - The notBefore date of the certificate.
 * @property {Date} notAfter - The notAfter date of the certificate.
 */

/** Get X.509 certificate validity dates.
 * @param  {ASNObj} cert - The top-level ASN.1 object representing the certificate.
 * @return {CertValidity} The certificate validity date object.
 * @throws {Error} If the number of found validity objects are not 2.
 */
function get_cert_validity(cert) {
    const a = traverse_ASN(cert, CERT_VALID_PATH, null, 0);
    if (a.length != 2) {
        throw `Failed to find validity in certificate`;
    }
    return {'notBefore': a[0].obj.value, 'notAfter': a[1].obj.value};
}

/** Path element array for the X.509 certificate subjectAltName's OID part.
 * @const {PathElementSpec[]}
 */
const SAN_PATH = ['Sequence[0]' /* TBSCertificate */,
    'Sequence[?]', 'Context-3[0]' /* Extensions */, 'Sequence[*]',
    /* Extension */ 'Sequence[0]', 'ObjectIdentifier'];

/** Get the subjectAltName's value part.
 * @param  {ASNObj} cert - The top-level ASN.1 object representing the certificate.
 * @return {SearchResult[]} The array fo SAN's value objects.
 * @throws {Error} If it fails to find SAN.
 */
function get_SAN_value(cert) {
    const values = traverse_ASN(cert, SAN_PATH, "2.5.29.17", 0);
    const l = values.length;
    if (l == 0) {
        throw `Invalid PEM certificate: missing subjectAltName (OID 2.5.29.17)`;
    } else if (l > 1) {
        throw `Failed to find SAN value in certificate: too many (${l}) subjectAltName (OID 2.5.29.17), expected 1`;
    }
    const obj = values[0];
    // Replace last 3 path elements ('Sequence[0]', 'Object-Identifier', ':value:')
    // with 'Sequence[1]', 'Octet-String[0]', 'Sequence[*]' to get SAN values.
    const ps = traverse_ASN(cert, obj.path.slice(0, -3).concat([
        'Sequence[1]', 'OctetString[0]', 'Sequence[*]']), null, 0);
    return ps;
}

/** Get X.509 certificate subjectAltName's values.
 * Certificate version is not checked which should be done by the caller.
 * @param  {ASNObj} cert - The top-level ASN.1 object representing the certificate.
 * @return {string[]} The array of subjectAltName's values.
 * @throws {Error} If it fails to find SAN.
 */
function get_cert_san(cert) {
    const info = get_SAN_value(cert);
    /** @type {string[]} */
    const  sans = [];
    for (let i = 0; i < info.length; i++) {
        sans.push(info[i].obj.value);
    }
    return sans;
}

/** Get the subjectAltName (SAN) strings from X.509 PEM certificate.
 * @param  {string} pem_cert - The PEM formatted string to be parsed.
 * @param  {number} index - The index of the certificate to get SAN from.
 * @param  {boolean} check_validity - check if the certificate is invalid.
 * @return {string[]} The array of SAN strings.
 * @throws {Error} If pem_cert is empty; index is invalid; wrong certificate version; or certificate is invalid.
 */
function get_san(pem_cert, index, check_validity) {
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
    return get_cert_san(cert);
}

/** Parse the PEM certificate content string.
 * @param  {string} der_str - The base64 string of the certificate.
 * @return {ASNObj} The top-level ASN.1 object representing the certificate. SAN is processed.
 * @throws {Error} If the certificate is invalid.
 */
function parse_cert(der_str) {
    const cert = asn1_read(Buffer.from(der_str, 'base64'));
    if (cert.length != 1) {
        throw `Invalid X.509 certificate: got ${cert.length} elements, expected 1`;
    }
    const values = get_SAN_value(cert[0]);
    for (let i = 0; i < values.length; i++) {
        process_san(values[i].obj);
    }
    return cert[0];
}

/** Parse one or more X.509 certificates in PEM format.
 * @param  {string} pem - The PEM formatted string to be parsed.
 * @return {ASNObj[]} The parsed certificate objects.
 * @throws {Error} If the PEM string doesn't contain the certificate pattern.
 */
function parse_pem_certs(pem) {
    const der = pem.split(/\n/);
    /** @type {ASNObj[]} */
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

/** Converts the HTTP header value to the PEM formatted string.
 * @param  {string} header - The HTTP header value containing the certificate which NLs are replaced by SP.
 * @return {string} The PEM formatted string.
 */
function header2pem(header) {
    var pem = header.replace(/(BEGIN|END) (CERT)/g, '\$1#\$2');
    pem = pem.replace(/ /g, '\n').replace(/#/g, ' ');
    if (pem[-1] != '\n') {
        pem += '\n';
    }
    return pem;
}

export default {asn1_read, parse_pem_certs, get_san, header2pem, get_SAN_value, get_cert_version, get_cert_validity,
    get_cert_san, traverse_ASN};
