module utils

import encoding.binary
import encoding.hex
import math.bits
import strings

pub fn parse_ipv4_route_ip_str(str string) !string {
  return hex.decode(str)!.reverse().map(it.str()).join('.')
}

pub fn parse_ipv4_route_mask_str(str string) !string {
  return bits.ones_count_32(binary.little_endian_u32(hex.decode(str)!)).str()
}

pub fn parse_ipv6_route_ip_str(str string) !string {
  mut result := []string{}
  for i in 0..(str.len_utf8() / 4) {
    seg := str[i * 4..i * 4 + 4].trim_left('0')
    result << if seg.len_utf8() > 0 { seg } else { '0' }
  }
  return result.join(':')
}

pub fn parse_ipv6_route_mask_str(str string) !string {
  return hex.decode(str)![0].str()
}

pub fn normalize_ip(str string) string {
  seg := str.split(':')
  if seg.len == 1 {
    return str
  }
  if seg.len < 8 {
    return str.replace('::', strings.repeat_string(':0', 9 - seg.len) + ':')
  } else {
    return str
  }
}
