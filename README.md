# adapter_engine

- 适配`pocsuite3`和`nuclei`的插件，用法请看测试文件。

## pocsuite3

1. 从文件加载插件`load_file_to_module`，参数`file_path`：pocsuite3插件的路径，` module_name=None`：pocsuite3的插件名称。
2. 从字符串加载`load_string_to_module`，参数`code_string`：pocsuite3插件文本字符串，`fullname=None`：pocsuites3的插件名称。

## nuclei

1. 从json对象加载插件`load_yaml_to_module`，参数`yaml_json`：插件序列化成json后的对象，`fullname=None`：插件的名称。**（使用第三方yaml库）**

## TODO

- nuclei的`dsl`和`interactsh_protocol`
