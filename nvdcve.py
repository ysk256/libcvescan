#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Require : requests, python-dateutil
import os
import sys
import codecs
import shutil
import json
import glob
import requests
import zipfile
import dateutil.parser

dnb = "data/"
def downloadCve(year = None, fnb = None ):
  if fnb is None:
    fnb = "nvdcve-1.0-%d.json"%year
  fnj = dnb + fnb
  fnjt = fnj + ".tmp"
  fnz = dnb + "nvdcve_tmp.zip"
  if os.path.isfile(fnz):
    os.remove(fnz)
  # https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.zip
  r = requests.get("https://nvd.nist.gov/feeds/json/cve/1.0/%s.zip"%fnb)
  if r is not None:
    open(fnz, "wb").write(r.content)
    if zipfile.is_zipfile(fnz):
      cveRaw = zipfile.ZipFile(fnz,"r").open(fnb).read()
      open(fnjt,"wb").write(cveRaw)
      shutil.move(fnjt, fnj)

def loadCve(fng = dnb + "nvdcve-1.0-*.json"):
  cveJson = []
  fns = sorted(glob.glob(fng))
  for fn in fns:
    cveJson += json.load(codecs.open(fn, "r", "utf-8"))["CVE_Items"]
  return cveJson

def cmpVersion(ver1, ver2):
  """
  return -1:ver1<ver2, 0:ver1==ver2, 1:ver1>ver2
  version format: * - 1 1.2 1.2.3 1.2.3ah  2018-01-16 v3 4.0\(1h\ 8.3(0)sk(0.39) 1.00(aaxm.6)c0
  
  """
  if ver1 == "-":
    ver1 = "*"
  if ver2 == "-":
    ver2 = "*"
  #
  if ver1 == ver2:
    return 0
  #
  if ver2 == "*":
    return -1
  elif ver1 == "*":
    return 1
  ver1 = ver1.split(".")
  ver2 = ver2.split(".")
  for i in range(min(len(ver1), len(ver2))):
    # parse ver item
    for j in range(1, len(ver1[i])+1):
      if ver1[i][:j].isdigit() == False:
        v1 = int(ver1[i][:j-1])
        v1a = ver1[i][j-1:]
        break
    else:
      v1 = int(ver1[i])
      v1a = ""
    for j in range(1, len(ver2[i])+1):
      if ver2[i][:j].isdigit() == False:
        v2 = int(ver2[i][:j-1])
        v2a = ver2[i][j-1:]
        break
    else:
      v2 = int(ver2[i])
      v2a = ""
    # comp a ver item
    if v1 == v2:
      if v1a == v2a:
        continue
      elif len(v1a) == len(v2a):
        # cmp alpha of a ver item
        for j in range(len(v1a)):
          if ord(v1a[j]) < ord(v2a[j]):
            return -1
          elif ord(v1a[j]) > ord(v2a[j]):
            return 1
        else:
          continue
      elif len(v1a) < len(v2a):
        return -1
      else:
        return 1
    elif v1 < v2:
      return -1
    else:
      return 1
  if len(ver1) < len(ver2):
    return -1
  elif len(ver1) > len(ver2):
    return 1
  return None # warinig

###
# getter
def getCveId(cveItem):
  cveId = None
  if cveItem is not None:
    cveId = cveItem["cve"]["CVE_data_meta"]["ID"]
  return cveId

def getDate(cveItem):
  # "publishedDate" : "2018-01-30T15:29Z",
  # "lastModifiedDate" : "2018-02-14T15:16Z"
  if cveItem is not None:
    publishedDate = cveItem["publishedDate"]
    lastModifiedDate = cveItem["lastModifiedDate"]
    return publishedDate, lastModifiedDate
  return None

def getCvssv2(cveItem):
  score = 0
  if cveItem is not None:
    if "baseMetricV2" in cveItem["impact"]:
      score = cveItem["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
      return score
  return None

def getCvssv3(cveItem):
  score = 0
  severity = ""
  if cveItem is not None:
    if "baseMetricV3" in cveItem["impact"]:
      score = cveItem["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
      severity = cveItem["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
      return (score, severity)
  return None

def getProductData(cveItem):
  # return productData = [[product_name, [[version_value, version_affected], ...]], ...]
  productData = []
  if cveItem is not None:
    vendor_data_array = cveItem["cve"]["affects"]["vendor"]["vendor_data"]
    for vendor_data in vendor_data_array:
      if len(vendor_data) > 0 and len(vendor_data["product"]["product_data"]) > 0:
        for productDataTmp in vendor_data["product"]["product_data"]:
          productData.append([productDataTmp["product_name"], productDataTmp["version"]["version_data"]])
  return productData

def getDesc(cveItem):
  cveDesc = ""
  if cveItem is not None:
    cveDesc = cveItem["cve"]["description"]["description_data"][0]["value"]
  return cveDesc

###
# find
def findCve(cveJson, cveId):
  for cveItem in cveJson:
    if cveId == cveItem["cve"]["CVE_data_meta"]["ID"]:
      return cveItem
  return None

def findCve2(cveJson, scoreMin, productNames = None, productVersions = None):
  cveItems = []
  for cveItem in cveJson:
    cveId = cveItem["cve"]["CVE_data_meta"]["ID"]
    score2 = getCvssv2(cveItem)
    score3 = getCvssv3(cveItem)
    if (score3 is not None and score3[0] > scoreMin
        or score2 is not None and score2 > scoreMin):
      if productNames is None:
        cveItems.append(cveItem)
      else:
        for name, versions in getProductData(cveItem):
          if name.lower() not in productNames:
            continue
          if productVersions is None:
            cveItems.append(cveItem)
          else:
            productVersion = productVersions[productNames.index(name.lower())]
            for versionDict in versions:
              versionValue, versionAffected  = versionDict["version_value"], versionDict["version_affected"]
              #print(productVersion, version)
              if versionAffected == "=":
                if productVersion == versionValue:
                  cveItems.append(cveItem)
                  break
              elif versionAffected == "<=":
                if cmpVersion(productVersion, versionValue) <= 0:
                  cveItems.append(cveItem)
                  break
              else:
                cveItems.append(cveItem)
                break
  return cveItems

###
# estimate
def estimateProductName(cveJson):
  productName = ""
  for cveItem in cveJson:
    pass

if __name__ == "__main__":
  if len(sys.argv) == 1:
    # download nvdcve-1.0-recent.json
    downloadCve(fnb="nvdcve-1.0-recent.json")
  elif len(sys.argv) == 2 and sys.argv[1].isdigit():
    # download nvdcve-1.0-YYYY.json
    year = int(sys.argv[1])
    downloadCve(year)
  elif len(sys.argv) >= 2:
    # Maching cve by product_name (and version)
    pds = sys.argv[1].lower().split(",")
    pdvs = sys.argv[2].split(",") if len(sys.argv) == 3 else None
    import time
    days = 60
    dateSpanTs = 60*60*24
    dateToTs = int(time.time() / dateSpanTs) * dateSpanTs
    dateFromTs = dateToTs - dateSpanTs*days
    cj = loadCve()
    fj = findCve2(cj, 7.0, pds, pdvs)
    for i in fj:
      id = getCveId(i)
      d = getDate(i)
      if d is not None:
        pd, md = d
        pdt = dateutil.parser.parse(pd).timestamp()
        mdt = dateutil.parser.parse(md).timestamp()
      #if pdt < dateFromTs:
      #  continue
      c = getCvssv3(i)
      ps = [name for name, versions in getProductData(i)]
      d = getDesc(i)
      for p in ps:
        if p.lower() not in pds:
          continue
        if c is not None:
          print(id.ljust(16), c[0], c[1][:4], p.ljust(15), d[:120])
        else:
          print(id.ljust(16), "***", "****", p.ljust(15), d[:120])
