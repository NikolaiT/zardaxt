import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('../database/tcp_ip.csv')
print(df)
print('unique ip_ttl', df['ip_ttl'].nunique())
print('unique tcp_options', df['tcp_options'].nunique())
print(df['tcp_options'].value_counts())
print(df['os_name'].value_counts())
print(df['tcp_window_size'].value_counts())
print(df['ip_ttl'].value_counts())
