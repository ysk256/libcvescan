#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Require : find, ldd/objdump/readelf, realpath of Linux command
import sys
import os
import subprocess

def get_bin_version(fn):
  """
  $ ls /lib/x86_64-linux-gnu/
  ld-2.23.so                libhistory.so.6.3          libpamc.so.0.82.1
  ld-linux-x86-64.so.2      libip4tc.so.0              libparted.so.2
  libBrokenLocale-2.23.so   libip4tc.so.0.1.0          libparted.so.2.0.1
  libBrokenLocale.so.1      libip6tc.so.0              libpci.so.3
  libSegFault.so            libip6tc.so.0.1.0          libpci.so.3.3.1
  libacl.so.1               libiptc.so.0               libpcprofile.so
  libacl.so.1.1.0           libiptc.so.0.0.0           libpcre.so.3
  libaio.so.1               libisc-export.so.160       libpcre.so.3.13.2
  libaio.so.1.0.1           libisc-export.so.160.0.0   libpcsclite.so.1
  libanl-2.23.so            libiw.so.30                libpcsclite.so.1.0.0
  libanl.so.1               libjson-c.so.2             libply-boot-client.so.4
  """
  fn = os.path.basename(fn)
  pos = fn.find(".so")
  if pos > 0 and len(fn) > pos+3 and fn[pos+3] == ".":
    # *.so.1.2.3
    bin_name = fn[:pos]
    ver = fn[pos+4:]
  elif pos > 0:
    pos2 = fn[:pos].rfind("-")
    if pos2 > 0:
      # *-1.2.3.so
      bin_name = fn[:pos2]
      ver = fn[pos2+1:pos]
    else:
      # *.so
      bin_name = fn[:pos]
      ver = ""
  else:
    # not *.so
    bin_name = fn
    ver = ""
  return [bin_name, ver]

def do_cmd(cmd):
  try:
    ret = subprocess.check_output(cmd, shell=True)
  except:
    ret = b""
  """
  cmd = ["ldd", "/bin/ls"]
  cmd = "ldd /bin/ls"
  p = subprocess.Popen(cmd,shell=True, stdin=subprocess.PIPE ,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  ret = p.stdout.read()
  ret = p.stderr.read()
  """
  return ret.decode("utf-8")

def cmd_realpath(fn):
  ret = do_cmd("realpath \"%s\""%fn)
  ret = ret.rstrip("\n")
  return ret

def cmd_find(dn):
  ret = do_cmd("find \"%s\" -executable -type f"%dn)
  for fpath in ret.split("\n"):
    if len(fpath) > 0:
      yield fpath
  return

def cmd_find_elf(dn):
  ret = cmd_find(dn)
  for fpath in ret:
    if open(fpath,"rb").read(4) == b"\x7FELF":
      yield fpath
  return

def cmd_readelf(fn):
  """
  $ readelf -r  lessecho
  
  Relocation section '.rela.dyn' at offset 0x6a0 contains 20 entries:
    Offset          Info           Type           Sym. Value    Sym. Name + Addend
  000000202008  000000000008 R_X86_64_RELATIVE                    202008
  000000201f88  000200000006 R_X86_64_GLOB_DAT 0000000000000000 putchar@GLIBC_2.2.5 + 0
  000000201f90  000300000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTMClone + 0
  """
  ret = do_cmd("readelf -r \"%s\""%fn)
  #print(ret)
  syms = []
  is_symbols = False
  for ln in ret.split("\n"):
    if is_symbols and len(ln) > 0:
      sym = ln[62:]
      if sym[0] == " ":
        continue # test
      sym = sym.strip(" ").rstrip(" ")
      sym = sym.split(" ")[0]
      syms.append(sym)
    elif ln.find("Offset") >= 0:
      is_symbols = True
  return syms

def cmd_objdump():
  """
  $ objdump -R lessecho
  
  lessecho:     file format elf64-x86-64
  
  DYNAMIC RELOCATION RECORDS
  OFFSET           TYPE              VALUE
  0000000000201d98 R_X86_64_RELATIVE  *ABS*+0x0000000000000e40
  0000000000201f88 R_X86_64_GLOB_DAT  putchar@GLIBC_2.2.5
  0000000000201f90 R_X86_64_GLOB_DAT  _ITM_deregisterTMCloneTable
  """
  ret = do_cmd("objdump -R \"%s\""%fn)
  #print(ret)
  syms = []
  is_symbols = False
  for ln in ret.split("\n"):
    if is_symbols and len(ln) > 0:
      sym = ln[36:]
      if sym.find("@") < 0:
        continue
      yield sym
    elif ln.find("OFFSET") >= 0:
      is_symbols = True
  return

def cmd_ldd(fn):
  """
  $ ldd lessecho
          linux-vdso.so.1 =>  (0x00007fffae74a000)
          libc.so.6 (0x00007f9fd3cce000)
          /lib64/ld-linux-x86-64.so.2 (0x00007f9fd429b000)
  """
  if os.path.isfile(fn) == False:
    return
  ret = do_cmd("ldd \"%s\""%fn)
  #print(ret)
  syms = []
  for ln in ret.split("\n"):
    ln = ln.strip("\t").strip(" ").rstrip("\t").rstrip(" ")
    if len(ln) > 0 and ln.find("statically linked") == -1:
      pos = ln.find("=>")
      pos2 = ln.find("(")
      if pos > 0 and pos2 - pos > 5:
        sym_name = ln[pos+3:pos2-1]
      else:
        sym_name = ln.split()[0]
      #print("debug", sym_name)
      sym_name_tmp = cmd_realpath(sym_name)
      if os.path.isfile(sym_name_tmp):
        sym_name = sym_name_tmp
      yield sym_name
  return

def main(dn):
  ldd_results = {}
  bin_names = []
  # search binary & ldd
  for fpath in cmd_find_elf(dn):
    # add binary path
    #print(fpath, "=====================")
    if fpath in ldd_results:
      continue
    bin_names.append(fpath)
    # ldd librarys of this binary path
    while len(bin_names) > 0:
      fpath2 = bin_names.pop()
      if fpath2 in ldd_results:
        continue
      bin_names2 = sorted(list(cmd_ldd(fpath2)))
      ldd_results[fpath2] = bin_names2
      #print("debug", fpath2, bin_names2)
      for fpath3 in bin_names2:
        if fpath3 not in bin_names:
          bin_names.append(fpath3)
    # show tree of the binary ldd_results
    if 1:
      def pprint_ldd(lib_path, indent = 0):
        bin_name, ver = get_bin_version(lib_path)
        print("  "*indent + lib_path + " " + ver)
        if lib_path in ldd_results:
          for lib_path2 in ldd_results[lib_path]:
            pprint_ldd(lib_path2, indent+1)
      print("=====================")
      pprint_ldd(fpath)
  # show each binary ldd_results
  if 0:
    for fpath, ldd_result in ldd_results.items():
      print(fpath, "=====================")
      for lib_path in ldd_result:
        print("  ", lib_path)

if __name__ == "__main__":
  dn = sys.argv[1]
  #main("/root/dev/tmp/")
  main(dn)
