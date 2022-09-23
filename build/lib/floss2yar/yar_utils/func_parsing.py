from collections import defaultdict
import logging
from multiprocessing.sharedctypes import Value
import subprocess
from curses import raw
from typing import Optional
import rzpipe
import json

from . import processing

def floss_func_parsing(file, score):
  print('parsing funcs with minimum score: ', score)
  analysis = FileAnalysis(file, [])
  funclist = processing.get_floss_funcs(file, score)
  rz = analysis.rz
  rz.cmd('aaaa')
  json_blob = rz.cmd('aflj')
  data = json.loads(json_blob)
  for func in data:
    for name in funclist:
      if name in func['name']:
        if func['size'] > 50:
          if func['size'] < 600:
            fun = FunctionFeature(rz, name)
            analysis.functions.append(fun)

  rz.cmd('q')
  return analysis


class FileAnalysis(object):
  """Holds the strategies and file information as well as the rz pipe"""

  def __init__(self, filepath:str, strategies:list):
    """"""
    self.rz = rzpipe.open(filepath)
    self.rz.cmd("aaaa")
    self.file_hash = json.loads(self.rz.cmd("itj"))['sha256']
    self.file_path = filepath

    self.strategies = []
    for each in strategies:
      if not issubclass(each, FunctionFinder):
        raise ValueError(f"{type(each)} is not a FunctionFinder")
      self.strategies.append(each)

    self.interesting_function_addrs = defaultdict(list)
    self.functions = []


  def get_functions(self):
    """Find funcitons in the file with the set strategies"""
    for strat in self.strategies:
      for addr, comments in strat.get_functions(self.file_path, self.rz).items():
        self.interesting_function_addrs[addr].extend(comments)

  def analyze_functions(self):
    """Create Function Features based on the unique addrs identified"""
    logging.debug(f"Analyzing {len(self.interesting_function_addrs)} functions")
    for addr in sorted(list(self.interesting_function_addrs.keys())):
      try:
        func = FunctionFeature(self.rz, addr)
      except:
        logging.exception(f"Failed to analyze function {addr}")
        continue
      self.functions.append(func)

  def quit_rizin(self):
    self.rz.cmd('q')

  def run(self) -> list:
    """Get and analyze functions, running this will close the rizin output since at this point File analysis should be done"""
    self.get_functions()
    self.analyze_functions()
    self.quit_rizin()
    return self.functions


class FunctionFinder(object):
  """Base class that is able to find interesting functions to consider for yara rules

  During operation of the yar2d2 we can have one or more of these be used at a time"""
  strategy_name = "UNDEFINED"

  @classmethod
  def get_functions(cls, filepath, rz):
    """Return a diction of function addresses with comments as to why they were added"""
    raise NotImplementedError


class FunctionFeature(object):
  """Class representing a function that we'll use to capture a function

  Notes:
    This will rely alot on the signature functionality of Rizin
    Details can be found here: https://book.rizin.re/signatures/zignatures.html"""

  def __init__(self, rz: rzpipe.open_sync.open, function_symbol):
    """Create a function feature with a pipe and a specific symobol or hexadecimal address"""

    # Check to see if the function symbol is an address or not
    symbol = None
    try:
      addr = int(function_symbol, 16)
      symbol = self.resolve_symbol_for_addr(rz, addr)
    except ValueError:
      symbol = function_symbol


    # Get File SHA256
    self.file = json.loads(rz.cmd("itj"))["sha256"]

    # Get highlevel function information
    rz.cmd(f"s {symbol}")
    raw_function_data = rz.cmd("afij")
    if len(raw_function_data) == 0:
      raise Exception(f"Couldn't parse information on {symbol}")
    function_data = json.loads(raw_function_data)
    if type(function_data) != list or len(function_data) != 1:
      raise Exception(f"Broken assumption on how the data should exist")
    function_data = function_data[0]

    self.name = function_data['name']
    self.size = function_data['size']
    self.signature = function_data['signature']

    # Get Dissassembly for comment string
    rz.cmd("e asm.bytes=true")
    self.disassembly = rz.cmd(f"pD {self.size}@ {self.name}")


    # Create the signature
    output = rz.cmd(f"zaf {symbol} {symbol}")

    #TODO some output checking here

    # Get the signature output
    raw_data = rz.cmd("zj")
    if len(raw_data) == 0:
      raise Exception(f"Failed to get data from signature for {symbol}")

    # Do some processing to make sure there's only one signature
    data = json.loads(raw_data)
    if len(data) == 1:
      data = data[0]
    else:
      data = list(filter(lambda x: (x['name'] == symbol),data))
      if len(data) != 1:
        raise Exception(f"More than one signatures matched {symbol}")
      data = data[0]

    # Load up the raw data
    self.sig_name = data["name"]
    self.bytes = bytes.fromhex(data['bytes'])
    self.mask = bytes.fromhex(data['mask'])
    self.graph = data['graph']
    self.addr = data['addr']
    # Default the realname to function symbol for now
    self.realname = data.get('realname', symbol)
    self.xrefs_from = data['xrefs_from']
    self.xrefs_to = data['xrefs_to']
    self.vars = data['vars']
    self.types = data['types']
    self.hash = data['hash']
    self._masked_asm_str = None

    # Delete the sig
    rz.cmd(f"z- {symbol}")

  @property
  def masked_asm_str(self) -> str:
    """Return an ascii hex string with ?? masking out parts of the instruction"""
    if self._masked_asm_str is not None:
      return self._masked_asm_str

    ret_str = []
    for x,y in zip(self.bytes, self.mask):
      if x & y == 0:
        ret_str.append("??")
      else:
        ret_str.append(f"{x & y:02X}")
    self._masked_asm_str = " ".join(ret_str)
    return self._masked_asm_str

  @property
  def yara_str(self) -> str:
    """Return a yara rule ready string"""
    return "$ = {{ {} }}".format(self.masked_asm_str)

  def resolve_symbol_for_addr(self, rz:rzpipe.open_sync.open, addr:int):
    """Attempt to resolve a symbol for the address

    Notes:
      If we don't have a function defined in rizin, we'll attempt to analzye the function
    """

    # Check to see if we have a function defined
    res = rz.cmd(f"afd @ {addr:#x}")
    if res == '':
      logging.debug(f"Warning defining a new function at {addr:#X}")
      rz.cmd(f"af @ {addr:#x}")

    # Seek to address
    rz.cmd(f"s {addr}")

    # Get function information
    fdata = json.loads(rz.cmd('afij'))
    if len(fdata) != 1:
      raise Exception(f"Broken assumption for addr {addr}")

    fdata = fdata[0]

    # Validate that the address is within offset and offset + size
    if addr < fdata['offset'] or addr > fdata['offset'] + fdata['size']:
      raise Exception(f"Broken Assumption: {addr:#X} outside of bounds {fdata['offset']:#X} < < {fdata['offset'] + fdata['size']:#X}")

    return fdata['name']



  def __str__(self) -> str:
    simple_features = dict(
      name=self.name,
      realname=self.realname,
      file=self.file,
      size=self.size,
      masked_asm_str=self.masked_asm_str,
      disassembly=self.disassembly
    )
    return json.dumps(simple_features)
