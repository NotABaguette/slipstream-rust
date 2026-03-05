use crate::base32;
use crate::dots;

use crate::name::{encode_name, extract_subdomain_multi, parse_name};
use crate::types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Rcode, ResponseParams, EDNS_UDP_PAYLOAD,
    RR_A, RR_AAAA, RR_OPT, RR_TXT,
};
use crate::wire::{
    parse_header, parse_question, parse_question_for_reply, read_u16, read_u32, write_u16,
    write_u32,
};

pub fn decode_query(packet: &[u8], domain: &str) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains(packet, &[domain])
}

pub fn decode_query_with_domains(
    packet: &[u8],
    domains: &[&str],
) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains_and_types(packet, domains, &[RR_TXT])
}

pub fn decode_query_with_domains_and_types(
    packet: &[u8],
    domains: &[&str],
    allowed_qtypes: &[u16],
) -> Result<DecodedQuery, DecodeQueryError> {
    let header = match parse_header(packet) {
        Some(header) => header,
        None => return Err(DecodeQueryError::Drop),
    };

    let rd = header.rd;
    let cd = header.cd;

    if header.is_response {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    if header.qdcount != 1 {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    let question = match parse_question(packet, header.offset) {
        Ok((question, _)) => question,
        Err(_) => return Err(DecodeQueryError::Drop),
    };

    if !allowed_qtypes.contains(&question.qtype) {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let subdomain_raw = match extract_subdomain_multi(&question.name, domains) {
        Ok(subdomain_raw) => subdomain_raw,
        Err(rcode) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode,
            })
        }
    };

    let undotted = dots::undotify(&subdomain_raw);
    if undotted.is_empty() {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let payload = match base32::decode(&undotted) {
        Ok(payload) => payload,
        Err(_) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode: Rcode::ServerFailure,
            })
        }
    };

    Ok(DecodedQuery {
        id: header.id,
        rd,
        cd,
        question,
        payload,
    })
}

pub fn encode_query(params: &QueryParams<'_>) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(256);
    let mut flags = 0u16;
    if !params.is_query {
        flags |= 0x8000;
    }
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, params.qdcount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    if params.qdcount > 0 {
        encode_name(params.qname, &mut out)?;
        write_u16(&mut out, params.qtype);
        write_u16(&mut out, params.qclass);
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn encode_response(params: &ResponseParams<'_>) -> Result<Vec<u8>, DnsError> {
    let qtype = params.question.qtype;
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);

    let mut rcode = params.rcode.unwrap_or(if payload_len > 0 {
        Rcode::Ok
    } else {
        Rcode::NameError
    });

    let answer_count = if payload_len > 0 && rcode == Rcode::Ok {
        answer_count_for_payload(qtype, payload_len)?
    } else {
        0
    };
    if answer_count == 0 && params.rcode.is_some() {
        rcode = params.rcode.unwrap_or(Rcode::Ok);
    }

    let mut out = Vec::with_capacity(256);
    let mut flags = 0x8000 | 0x0400;
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }
    flags |= rcode.to_u8() as u16;

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, answer_count);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(&params.question.name, &mut out)?;
    write_u16(&mut out, params.question.qtype);
    write_u16(&mut out, params.question.qclass);

    if answer_count > 0 {
        if let Some(payload) = params.payload {
            encode_answer_records(&mut out, params.question, payload)?;
        }
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn decode_response(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(packet)?;
    if !header.is_response {
        return None;
    }
    let rcode = header.rcode?;
    if rcode != Rcode::Ok {
        return None;
    }
    if header.ancount < 1 {
        return None;
    }

    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }

    let mut qtype: Option<u16> = None;
    let mut out = Vec::new();
    for _ in 0..header.ancount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 10 > packet.len() {
            return None;
        }
        let answer_type = read_u16(packet, offset)?;
        offset += 2;
        let _qclass = read_u16(packet, offset)?;
        offset += 2;
        let _ttl = read_u32(packet, offset)?;
        offset += 4;
        let rdlen = read_u16(packet, offset)? as usize;
        offset += 2;
        if offset + rdlen > packet.len() {
            return None;
        }
        if qtype.is_none() {
            qtype = Some(answer_type);
        }
        if Some(answer_type) != qtype {
            return None;
        }

        match answer_type {
            RR_TXT => {
                if rdlen < 1 {
                    return None;
                }
                let mut remaining = rdlen;
                let mut cursor = offset;
                while remaining > 0 {
                    let txt_len = packet[cursor] as usize;
                    cursor += 1;
                    remaining -= 1;
                    if txt_len > remaining {
                        return None;
                    }
                    out.extend_from_slice(&packet[cursor..cursor + txt_len]);
                    cursor += txt_len;
                    remaining -= txt_len;
                }
            }
            RR_A => {
                if rdlen != 4 {
                    return None;
                }
                out.extend_from_slice(&packet[offset..offset + rdlen]);
            }
            RR_AAAA => {
                if rdlen != 16 {
                    return None;
                }
                out.extend_from_slice(&packet[offset..offset + rdlen]);
            }
            _ => return None,
        }
        offset += rdlen;
    }
    if out.is_empty() {
        return None;
    }

    match qtype? {
        RR_TXT => Some(out),
        RR_A | RR_AAAA => decode_ip_payload(&out),
        _ => None,
    }
}

pub fn is_response(packet: &[u8]) -> bool {
    parse_header(packet)
        .map(|header| header.is_response)
        .unwrap_or(false)
}

fn encode_opt_record(out: &mut Vec<u8>) -> Result<(), DnsError> {
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    write_u16(out, 0);
    Ok(())
}

fn answer_count_for_payload(qtype: u16, payload_len: usize) -> Result<u16, DnsError> {
    match qtype {
        RR_TXT => Ok(1),
        RR_A => answer_count_for_chunk(payload_len, 4),
        RR_AAAA => answer_count_for_chunk(payload_len, 16),
        _ => Err(DnsError::new("unsupported query type")),
    }
}

fn answer_count_for_chunk(payload_len: usize, chunk_len: usize) -> Result<u16, DnsError> {
    let framed_len = payload_len
        .checked_add(2)
        .ok_or_else(|| DnsError::new("payload too long"))?;
    let count = framed_len.div_ceil(chunk_len);
    u16::try_from(count).map_err(|_| DnsError::new("too many answers"))
}

fn encode_answer_records(
    out: &mut Vec<u8>,
    question: &crate::types::Question,
    payload: &[u8],
) -> Result<(), DnsError> {
    match question.qtype {
        RR_TXT => encode_txt_answer(out, question, payload),
        RR_A => encode_ip_answers(out, question, payload, 4),
        RR_AAAA => encode_ip_answers(out, question, payload, 16),
        _ => Err(DnsError::new("unsupported query type")),
    }
}

fn encode_txt_answer(
    out: &mut Vec<u8>,
    question: &crate::types::Question,
    payload: &[u8],
) -> Result<(), DnsError> {
    out.extend_from_slice(&[0xC0, 0x0C]);
    write_u16(out, question.qtype);
    write_u16(out, question.qclass);
    write_u32(out, 60);
    let payload_len = payload.len();
    let chunk_count = payload_len.div_ceil(255);
    let rdata_len = payload_len + chunk_count;
    if rdata_len > u16::MAX as usize {
        return Err(DnsError::new("payload too long"));
    }
    write_u16(out, rdata_len as u16);
    let mut remaining = payload_len;
    let mut cursor = 0;
    while remaining > 0 {
        let chunk_len = remaining.min(255);
        out.push(chunk_len as u8);
        out.extend_from_slice(&payload[cursor..cursor + chunk_len]);
        cursor += chunk_len;
        remaining -= chunk_len;
    }
    Ok(())
}

fn encode_ip_answers(
    out: &mut Vec<u8>,
    question: &crate::types::Question,
    payload: &[u8],
    chunk_len: usize,
) -> Result<(), DnsError> {
    if payload.len() > u16::MAX as usize {
        return Err(DnsError::new("payload too long"));
    }
    let mut framed = Vec::with_capacity(payload.len() + 2);
    framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    framed.extend_from_slice(payload);

    let mut offset = 0usize;
    while offset < framed.len() {
        out.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(out, question.qtype);
        write_u16(out, question.qclass);
        write_u32(out, 60);
        write_u16(out, chunk_len as u16);

        let remaining = framed.len() - offset;
        let take = remaining.min(chunk_len);
        out.extend_from_slice(&framed[offset..offset + take]);
        if take < chunk_len {
            out.resize(out.len() + (chunk_len - take), 0);
        }
        offset += take;
    }
    Ok(())
}

fn decode_ip_payload(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 2 {
        return None;
    }
    let payload_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    if payload_len == 0 {
        return None;
    }
    if raw.len() < payload_len + 2 {
        return None;
    }
    Some(raw[2..2 + payload_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::encode_response;
    use crate::types::{Question, ResponseParams, CLASS_IN, RR_TXT};

    #[test]
    fn encode_response_rejects_large_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_TXT,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; u16::MAX as usize];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
        };
        assert!(encode_response(&params).is_err());
    }
}
