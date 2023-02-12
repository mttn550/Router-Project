import pandas as pd


rib = pd.DataFrame(data=[[1,2,3,4]], columns=['Destination', 'Mask', 'Gateway', 'Metric'])
rib2 = pd.DataFrame(data=[[5,6,7,8]], columns=['Destination', 'Mask', 'Gateway', 'Metric'])
rib = rib.append(rib2)

print(rib[0:1]['Destination'].values)