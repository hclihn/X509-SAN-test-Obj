/** x509.js
 * ASN.1 DER X509 certificate parsing and manipulation.
 * Adopted from https://github.com/nginx/njs-examples (njs/http/certs/js/x509.js)
 * with bug fixes and enhancements.
 */

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

      if (sid > Number.MAX_SAFE_INTEGER)
        throw "Too big SID value: " + sid;
      // end of the OID field
      oid.push(sid);
      sid = 0;
    } else {
      sid += cur_octet & 0x7f; sid <<= 7;

      if (sid > Number.MAX_SAFE_INTEGER)
        throw "Too big SID value: " + sid;
    }
  }

  if (buf[buf.length-1] >= 0x80)
    throw "Last octet in oid buffer has highest bit set to 1";

  return oid.join('.')
}

/**
 * Parse ASN.1 DER Integer.
 * @param  {Buffer} buf - The DER Integer value to be parsed.
 * @return {number|string} The integer value.
 *   If the length is logner than 6 bytes, it return the hex string representation.
 */
function asn1_parse_integer(buf) {
  if (buf.length > MAX_INT_BYTES) {
    // may exceed MAX_SAFE_INTEGER, lets return hex
    return asn1_parse_any(buf);
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

  return (is_negative)? (value - compl_int) : value;
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
  if (is_ia5(buf))
    return buf.toString();
  else
    throw "Not a IA5String: " + buf;
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
  if (buf[0] == 0)
    return buf.slice(1);

  const shift = buf[0];
  if (shift > 7)
    throw "Incorrect shift in bitstring: " + shift;

  var value = Buffer.allocUnsafe(buf.length - 1);
  var upper_bits = 0;
  const mask = ((1 << shift) - 1) & 0xff;
  
  // shift string right and convert to hex
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
    if (buf[n] > 0x7e)
      return false;
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
  var s = buf[pointer];
  var length = 0;
  if (s == 0x80 || s == 0xff)
    throw "indefinite length is not supported";

  if (s < 0x80) {
    // length is less than 128
    pointer++;
    return [s, pointer];
  } else {
    var l = s & 0x7f;
    if (l > (MAX_INT_BYTES + 1))
      throw "Too big length, exceeds MAX_SAFE_INTEGER: " + l;

    if ((pointer + l) >= buf.length)
      throw "Went out of buffer: " + (pointer + l) + " " + buf.length;

    for (let n = 0; n < l; n++) {
      length = (length * 256) + buf[++pointer];
      if (n == MAX_INT_BYTES && buf[pointer] > MAX_INT_REM_VAL)
        throw "Too big length, exceeds MAX_SAFE_INTEGER";
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
    throw "Not an IPv4 address: " + buf;
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
    throw "Not an IPv6 address: " + buf;
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

/**
 * Parse ASN.1 DER primitive.
 * @param  {number} cls - The DER class.
 * @param  {number} tag - The DER tag.
 * @param  {Buffer} buf - The DER value to be parsed.
 * @return {string|number|CertType} The parsed value.
 */
function asn1_parse_primitive(cls, tag, buf) {
  if (cls == 0) { // non-constructed only!
    switch(tag) {
    // INTEGER
    case 0x02: return asn1_parse_integer(buf);
    // BIT STRING
    case 0x03:
      // get the BitSting value first, then try to see if we can parse
      // the DER substructure. If not, then return the hex representation.
      const data = asn1_parse_bit_string(buf);
      try {
        return asn1_read(data);
      } catch(e) {
        return data.toString('hex');
      }
    // OCTET STRING
    case 0x04:
      // Try to see if we can parse the DER substructure. 
      // If not, then return the hex representation.
      try {
        return asn1_read(buf);
      } catch(e) {
        return asn1_parse_octet_string(buf);
      }
    // OBJECT IDENTIFIER
    case 0x06: return asn1_parse_oid(buf);
    // UTF8String
    case 0x0c: return asn1_parse_utf8_string(buf);
    // TIME
    case 0x0e:
    // NumericString
    case 0x12:
    // PrintableString
    case 0x13:
    // T61String
    case 0x14:
    // VideotexString
    case 0x15:
     return asn1_parse_ascii_string(buf);
    // IA5String
    case 0x16: return asn1_parse_ia5_string(buf);
    // UTCTime
    case 0x17:
    // GeneralizedTime
    case 0x18:
    // GraphicString
    case 0x19:
    // VisibleString
    case 0x1a:
    // GeneralString
    case 0x1b:
     return asn1_parse_ascii_string(buf);
    // UniversalString
    case 0x1c: return asn1_parse_universal_string(buf);
    // CHARACTER STRING
    case 0x1d: return asn1_parse_ascii_string(buf);
    // BMPString
    case 0x1e: return asn1_parse_bmp_string(buf);
    // DATE
    case 0x1f:
    // TIME-OF-DAY
    case 0x20:
    // DATE-TIME
    case 0x21:
    // DURATION
    case 0x22:
      return asn1_parse_ascii_string(buf);
    default: return asn1_parse_any(buf);
    }
  } else if (cls == 2) { // context specific, non-constructed
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
    // This is mainly for SANs, but other parts of the cert can also be applied. Be very careful!
    switch(tag) {
    case 0x00: return asn1_parse_any(buf);
    case 0x01: return asn1_parse_ascii_string(buf);
    case 0x02: return asn1_parse_ascii_string(buf);
    case 0x06: return asn1_parse_ascii_string(buf);
    case 0x07: 
      if (buf.length == 4) { // IPv4 address
        return format_ipv4(buf);   
      } else if (buf.length == 16) { // IPv6 address
        return format_ipv6(buf);
      }
      return asn1_parse_any(buf);
    default: return asn1_parse_any(buf);
    }
  }

  return asn1_parse_any(buf);
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
  var s = "";
  var length;

  while (pointer < buf.length) {
    // read type: 7 & 8 bits define class, 6 bit if it is constructed
    s = buf[pointer];
    tag_class = s >> 6;
    is_constructed = s & 0x20;
    tag = s & 0x1f;

    if (tag == 0x1f) {
      tag = 0;
      let i = 0;

      do {
        if (i > 3)
          throw "Too big tag value" + tag;

        i++;

        if (++pointer >= buf.length)
          throw "Went out of buffer: " + pointer + " " + buf.length;

        tag <<= 7;
        tag += (buf[pointer] & 0x7f);

      } while (buf[pointer] > 0x80);
    }

    if (++pointer > buf.length)
       throw "Went out of buffer: " + pointer + " " + buf.length;

    var lp = asn1_read_length(buf, pointer);
    length = lp[0];
    pointer = lp[1];

    if ((pointer + length) > buf.length)
       throw "length exceeds buf side: " + length + " " + pointer + " "
         +  buf.length;

    if (is_constructed) {
      a.push(asn1_read(buf.slice(pointer, pointer + length)));

    } else {
      a.push(asn1_parse_primitive(tag_class, tag,buf.slice(pointer, pointer + length)));
    }

    pointer += length;
  }

  return a;
}

/**
 * Test if the OID exists in cert.
 * @param  {CertType} cert - The parsed X.509 certificate to be searched.
 * @param  {string} oid - The OID to look up.
 * @return {boolean} True if the OID exists in cert.
 */
function is_oid_exist(cert, oid) {
  for (var n = 0; n < cert.length; n++) {
    if (Array.isArray(cert[n])) {
      if (is_oid_exist(cert[n], oid))
        return true;
    } else if (cert[n] == oid)
        return true;
  }

  return false;
}


/**
 * Get all the values of the matching specified OID.
 * @param  {CertType} cert - The parsed X.509 certificate to be searched.
 * @param  {string} oid - The OID to look up.
 * @return {CertType[]} The array of values matching the specified OID.
 */
function get_oid_value_all(cert, oid) {
  var values = [];

  for (let n = 0; n < cert.length; n++) {
    if (Array.isArray(cert[n])) {
      let r = get_oid_value_all(cert[n], oid);
      if (r.length > 0) {
        values = values.concat(r);
      }
    } else if (cert[n] == oid) {
      if (n < cert.length) {
        // push next element in array
        values.push(cert[n+1]);
      }
    }
  }

  return values;
}

/**
 * Get the value of the first matching specified OID.
 * @param  {CertType} cert - The parsed X.509 certificate to be searched.
 * @param  {string} oid - The OID to look up.
 * @return {CertType} The value of the specified OID.
 */
function get_oid_value(cert, oid) {
  for (let n = 0; n < cert.length; n++) {
    if (Array.isArray(cert[n])) {
      let r = get_oid_value(cert[n], oid);
      if (r !== false)
        return r;
    } else if (cert[n] == oid) {
      if (n < cert.length) {
        // return next element in array
        return cert[n+1];
      }
    }
  }

  return false;
}

/**
 * Parse X.509 certificate in PEM format.
 * @param  {string} pem - The PEM string to be parsed.
 * @return {CertType} The parsed certificate in a multi-level array.
 *   Values are in strings or numbers.
 */
function parse_pem_cert(pem) {
  var der = pem.split(/\n/);

  if (pem.match('CERTIFICATE')) {
    der = der.slice(1, -2);
  }

  return asn1_read(Buffer.from(der.join(''), 'base64'));
}

export default {asn1_read, parse_pem_cert, is_oid_exist, get_oid_value, get_oid_value_all};
  