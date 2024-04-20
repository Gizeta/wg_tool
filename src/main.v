module main

import os
import prantlf.ini
import regex
import utils

struct WgPeer {
  public_key  string
  allowed_ips []string
}

struct WgConf {
  name    string
  address []string
mut:
  peers   []WgPeer
}

struct RouteRule {
  dest    string
  gateway string
}

struct ChangeParam {
  public_key  string
mut:
  allowed_ips string
}

fn find_net_dev() []string {
  net_dev_txt := os.read_file('/proc/net/dev') or {
    println('failed to read net interfaces')
    return []
  }
  mut re := regex.regex_opt(r'wg\d+') or { panic(err) }
  return re.find_all_str(net_dev_txt)
}

fn read_wg_conf(name string) !WgConf {
  wg_conf_txt := os.read_file('/etc/wireguard/' + name + '.conf') or {
    return error('failed to read wireguard conf: ' + name)
  }
  wg_conf := ini.parse_readable(wg_conf_txt) or {
    return error('failed to parse wireguard conf: ' + name)
  }

  mut conf := WgConf{
    name,
    wg_conf.section_prop_val('Interface', 'Address') or { '' }.split(',').map(it.trim(' ')),
    []
  }

  mut sections := wg_conf.sections()
  for sections.is_valid() {
    if sections.has('PublicKey') {
      conf.peers << WgPeer{
        sections.prop_val('PublicKey') or { '' },
        sections.prop_val('AllowedIPs') or { '' }.split(',').map(utils.normalize_ip(it.trim(' ')))
      }
    }
    sections.next()
  }
  return conf
}

fn get_system_route(name string) []RouteRule {
  mut rules := []RouteRule{}
  route_txt := os.read_file('/proc/net/route') or {
    println('failed to read system route table')
    return rules
  }
  for line in route_txt.split('\n') {
    if line.starts_with(name) {
      row := line.split_any('\t ').filter(it != '')
      if row[2] != '00000000' {
        rules << RouteRule{
          utils.parse_ipv4_route_ip_str(row[1]) or { continue } + '/' + utils.parse_ipv4_route_mask_str(row[7]) or { continue },
          utils.parse_ipv4_route_ip_str(row[2]) or { continue } + '/32'
        }
      }
    }
  }

  route6_txt := os.read_file('/proc/net/ipv6_route') or {
    println('failed to read system ipv6 route table')
    return rules
  }
  for line in route6_txt.split('\n') {
    if line.ends_with(name) {
      row := line.split_any('\t ').filter(it != '')
      if row[4] != '00000000000000000000000000000000' {
        rules << RouteRule{
          utils.parse_ipv6_route_ip_str(row[0]) or { continue } + '/' + utils.parse_ipv6_route_mask_str(row[1]) or { continue },
          utils.parse_ipv6_route_ip_str(row[4]) or { continue } + '/128'
        }
      }
    }
  }
  return rules
}

fn append_allowed_ip(mut params []ChangeParam, public_key string, ip string) {
  for mut item in params {
    if item.public_key == public_key {
      item.allowed_ips += ',' + ip
      return
    }
  }
  params << ChangeParam{
    public_key,
    ip
  }
}

fn calc_allowed_ips(conf WgConf, rules []RouteRule) []ChangeParam {
  mut scheduled_ips := []string{}

  mut params := []ChangeParam{}
  for rule in rules {
    for peer in conf.peers {
      if peer.allowed_ips.contains(rule.gateway) {
        if !scheduled_ips.contains(rule.dest) {
          append_allowed_ip(mut params, peer.public_key, rule.dest)
          scheduled_ips << rule.dest
        }
      }
    }
  }

  for peer in conf.peers {
    for addr in peer.allowed_ips {
      if !scheduled_ips.contains(addr) {
        append_allowed_ip(mut params, peer.public_key, addr)
      }
    }
  }

  return params
}

fn set_allowed_ip(name string, public_key string, allowed_ips string) {
  os.execute('wg set $name peer $public_key allowed-ips $allowed_ips')
}

fn main() {
  net_devs := find_net_dev()
  if net_devs.len == 0 {
    println('cannot find wireguard interface')
    return
  }
  for name in net_devs {
    println('found interface: ' + name)
    wg_conf := read_wg_conf(name) or {
      println(err)
      continue
    }
    rules := get_system_route(name)
    change_params := calc_allowed_ips(wg_conf, rules)
    for param in change_params {
      set_allowed_ip(name, param.public_key, param.allowed_ips)
    }
  }
}
