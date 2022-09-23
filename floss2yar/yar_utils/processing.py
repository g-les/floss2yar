from datetime import date
from unicodedata import name
import floss
import viv_utils
from floss import identify


def yara_builder(list_of_input_functions, name_arg):
  if name_arg is not None:
    name_arg = str(name_arg)
    rule_name_str = "\nrule " + name_arg + '_floss2yar_'
  else:
    rule_name_str = '\nrule floss2yar_'
  rule_str = ""
  today = date.today().isoformat()
  for input_function in list_of_input_functions:
    disass = input_function['disass']
    yara_strang = input_function['yara_str']
    yara_str_name = input_function['func_name']
    todaydate = 'date = "' + today + '"'
    rule_setup = rule_name_str + yara_str_name + ' {\nmeta:\n\tauthor = "floss2yar"\n\t' + todaydate + '\n\tversion = "1.0"\n'
    rule_str += rule_setup
    hash_list = sorted(list(set(input_function['samples'])))
    for f in hash_list:
      e = f.strip()
      rule_str += f'\thash = "{e}"\n'
    rule = '\nstrings: \n' + '\t$' + yara_str_name + ' = {' + yara_strang + '}\n /* \n' + disass + '\n */ \ncondition: \n\t1 of them \n}'
    rule_str += rule
    rule_str += "\n\n"
  print(rule_str)
  return rule_str

def get_floss_funcs(file, min_score):
  if min_score is None:
    min_score = 0.90
  min_scoring = float(min_score)
  print('[+] parsing funcs with minimum score: ', min_scoring)
  candidates = []
  vw = viv_utils.getWorkspace(file)
  functions = vw.getFunctions()
  func_features, lib_funcs = floss.identify.find_decoding_function_features(vw, functions)
  # dict from function VA (int) to score (float)
  func_scores = {
      fva: features["score"]
      for fva, features in func_features.items()
  }
  # list of tuples (score (float), function VA (int)) sorted descending
  func_scores = sorted([
       (score, fva)
       for fva, score in func_scores.items()
  ], reverse=True)
  for score, fva in func_scores:
    if score > min_scoring: 
      offset = f"{fva:x}"
      func = offset.lower()
      candidates.append(func)
  return candidates


def data_processing(blob_of_data, name_arg):
  print('[+] trying to process data')
  final_yara_list = {}
  for sample in blob_of_data.functions:
    yara_input = {}
    yara_input['samples'] = []
    sample.realname = sample.realname.replace('.', '_')
    yara_input['func_name'] = sample.realname
    yara_input['yara_str'] = sample.masked_asm_str
    yara_input['disass'] = sample.disassembly
    yara_input['samples'].append(sample.file)
    final_yara_list[sample] = yara_input

  final_yara_list = [v for k,v in final_yara_list.items()]
  return yara_builder(final_yara_list, name_arg)
