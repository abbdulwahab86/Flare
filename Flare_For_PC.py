# -*- coding: utf-8 -*-
"""
Created on Fri Mar 15 16:08:12 2019

@author: ButterFactory
"""

import numpy as np
import pandas as pd
from scipy.stats import norm
import time
import os.path
import sys
import csv
from pandas import DataFrame




class Flare:
    def __init__(self,file_path,limit,grace_period,):
        self.FE = FE(file_path,limit)
        self.Detect = GMM(32,grace_period)

    def proc_next_packet(self):
        # create feature vector
        x = self.FE.get_next_vector()
        
        if len(x) == 0:
            return -1 #Error or no packets left
        # process KitNET
        return self.Detect.process(x)  # will train during the grace periods, then execute on all the rest.



class FE:
    def __init__(self,file_path,limit=np.inf):
        self.path = file_path
        self.limit = limit
        self.parse_type = None #unknown
        self.curPacketIndx = 0
        self.tsvin = None #used for parsing TSV file
        ### Prep pcap ##
        self.__prep__()

    def clean_dataset(df):
        assert isinstance(df, pd.DataFrame)
        df.dropna(inplace=True)
        indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
        return df[indices_to_keep].astype(np.float64).reset_index()
    def __prep__(self):
        ### Find file: ###
        if not os.path.isfile(self.path):  # file does not exist
            print("File: " + self.path + " does not exist")
            raise Exception()

        ### check file type ###
        type = self.path.split('.')[-1]

        ##If file is TSV 
        if type == "csv":
            self.parse_type = "csv"
        ### open readers ##
        if self.parse_type == "csv":
            maxInt = sys.maxsize
            decrement = True
            while decrement:
                # decrease the maxInt value by factor 10
                # as long as the OverflowError occurs.
                decrement = False
                try:
                    csv.field_size_limit(maxInt)
                except OverflowError:
                    maxInt = int(maxInt / 10)
                    decrement = True

            print("counting lines in file...")
            num_lines = sum(1 for line in open(self.path))
            print("There are " + str(num_lines) + " Events.")
            self.limit = min(self.limit, num_lines-1)
            self.tsvinf = open(self.path, 'rt')
            self.tsvin = csv.reader(self.tsvinf, delimiter=',')
            row = self.tsvin.__next__() #move iterator past header 

        else: 
            print("File format is not csv")
    def get_next_vector(self):
        if self.curPacketIndx == self.limit:
            if self.parse_type == 'tsv':
                self.tsvinf.close()
            return []

        ### Parse next packet ###
        if self.parse_type == "csv":
            row = self.tsvin.__next__()
#            cpaa=	(float(row[7]))
#            cpab=	(float(row[9]))
#            cpac=	(float(row[11]))
#            cpma=	(float(row[8]))
#            cpmb=	(float(row[10]))
#            cpmc=	(float(row[12]))
#            csaa=	(float(row[19]))
#            csab=	(float(row[21]))
#            csac=	(float(row[23]))
#            csma=	(float(row[20]))
#            csmb=	(float(row[22]))
#            csmc=	(float(row[24]))
#            ra=		(float(row[27]))
#            rf=		(float(row[25]))
#            rfd=	(float(row[26]))
#            ria=	(float(row[28]))
#            vpaa=	(float(row[1]))
#            vpab	=(float(row[3]))
#            vpac	=(float(row[5]))
#            vpma=(float(row[2]))
#            vpmb=	(float(row[4]))
#            vpmc=	(float(row[6]))
#            vsaa=	(float(row[13]))
#            vsab=	(float(row[15]))
#            vsac=	(float(row[17]))
#            vsma=	(float(row[14]))
#            vsmb=	(float(row[16]))
#            vsmc=(float(row[18]))
            vsmc	=(float(row[18])+float(row[46])+float(row[74])+float(row[102]))/4
            vsmb	=(float(row[16])+float(row[44])+float(row[72])+float(row[100]))/4
            vsma	=(float(row[14])+float(row[42])+float(row[70])+float(row[98]))/4
            cpmc	=(float(row[12])+float(row[40])+float(row[68])+float(row[96]))/4
            cpmb	=(float(row[10])+float(row[38])+float(row[66])+float(row[94]))/4
            cpma	=(float(row[8])+float(row[36])+float(row[64])+float(row[92]))/4
            vpmc	=(float(row[6])+float(row[34])+float(row[62])+float(row[90]))/4
            vpmb	=(float(row[4])+float(row[32])+float(row[60])+float(row[88]))/4
            csmc	=(float(row[24])+float(row[52])+float(row[80])+float(row[108]))/4
            csmb	=(float(row[22])+float(row[50])+float(row[78])+float(row[106]))/4
            csma	=(float(row[20])+float(row[48])+float(row[76])+float(row[104]))/4
            vpma	=(float(row[2])+float(row[30])+float(row[58])+float(row[86]))/4
            vsac	=(float(row[17])+float(row[45])+float(row[73])+float(row[101]))/4
            vsab	=(float(row[15])+float(row[43])+float(row[71])+float(row[99]))/4
            vsaa	=(float(row[13])+float(row[41])+float(row[69])+float(row[97]))/4
            cpac	=(float(row[11])+float(row[39])+float(row[67])+float(row[95]))/4
            cpab	=(float(row[9])+float(row[37])+float(row[65])+float(row[93]))/4
            cpaa	=(float(row[7])+float(row[35])+float(row[63])+float(row[91]))/4
            vpac	=(float(row[5])+float(row[33])+float(row[61])+float(row[89]))/4
            vpab	=(float(row[3])+float(row[31])+float(row[59])+float(row[87]))/4
            csac	=(float(row[23])+float(row[51])+float(row[79])+float(row[107]))/4
            csab	=(float(row[21])+float(row[49])+float(row[77])+float(row[105]))/4
            csaa	=(float(row[19])+float(row[47])+float(row[75])+float(row[103]))/4
            vpaa	=(float(row[1])+float(row[29])+float(row[57])+float(row[85]))/4
            ria	=(float(row[28])+float(row[56])+float(row[84])+float(row[112]))/4
            ra	=(float(row[27])+float(row[55])+float(row[83])+float(row[111]))/4
            rf	=(float(row[25])+float(row[53])+float(row[81])+float(row[109]))/4
            rfd	=(float(row[26])+float(row[54])+float(row[82])+float(row[110]))/4
            rs	=(float(row[29])+float(row[58])+float(row[87])+float(row[116]))/4
            cpl	=(float(row[117])+float(row[118])+float(row[119])+float(row[120]))/4
            rl	=(float(row[121])+float(row[122])+float(row[123])+float(row[124]))/4
            sl	=(float(row[125])+float(row[126])+float(row[127])+float(row[128]))/4

        else:
            return []

        self.curPacketIndx = self.curPacketIndx + 1


        ### Extract Features
        try:
            return [cpaa,cpab,cpac,cpma,cpmb,cpmc,csaa,csab,csac,
                    csma,csmb,csmc,ra,rf,rfd,ria,vpaa,vpab,vpac,
                    vpma,vpmb,vpmc,vsaa,vsab,vsac,vsma,vsmb,vsmc,
                    rs,cpl,rl,sl]
        except Exception as e:
            print(e)
            return []

class GMM:
    def __init__(self,n,AD_grace_period):
        # Parameters:
        self.AD_grace_period = AD_grace_period
        self.n = n
        self.n_trained = 0# 0 # the number of training instances so far
        self.n_executed = 0 # the number of executed instances so far
        self.Train_Mat= []
        self.Ex_Mat=[]
        self.count = 0
        self.count2=0
        self.window=120
        self.drlist=[]
        self.fprlist=[]
        
    def process(self,x):
        if self.n_trained >= self.AD_grace_period: #If both the FM and AD are in execute-mode
            self.count2 += 1        
            if (self.count2) <= self.window:
                self.Ex_Mat.append(x)
#                self.n_trained += 1
            if self.count2 == self.window:
                self.count2 = 0
#                self.n_trained += 1
                return self.execute(self.Ex_Mat)
        else:
            self.count += 1
            if self.count < self.AD_grace_period:
                self.Train_Mat.append(x)
#                self.n_trained += 1
            if self.count == self.AD_grace_period:
                self.n_trained += 1
                ret = self.train(self.Train_Mat)
                stop1 = time.time()
                print("Time elapsed in Trg: "+ str(stop1 - start))
                return ret
        self.n_trained += 1
        return
    #force train KitNET on x
    #returns the anomaly score of x during training (do not use for alerting)
  
    def train(self,dataset):
        dataset=pd.DataFrame(dataset)
        dataset=FE.clean_dataset(dataset)
        dataset=dataset.drop(['index'], axis=1)
        
        # from sklearn.preprocessing import MinMaxScaler
        # rows = dataset.shape[0];
        # columns= dataset.shape[1];
        # for i in range(0,columns):
            # values = dataset[i].values
            # values = values.reshape((len(values), 1))
            # scaler = MinMaxScaler(feature_range=(0, 1))
            # scaler = scaler.fit(values)
            # print('Min: %f, Max: %f' % (scaler.data_min_, scaler.data_max_))
            # dataset[i] = scaler.transform(values)
        pd.set_option('precision',7);
        self.m=dataset.mean(); # --- Mean (µ)
        self.s=dataset.std();  # --- Standard daviation (σ)
        self.v=self.s*self.s;            # --- Variance (𝜎^2)
        self.w=1/dataset.shape[1];
        rows = dataset.shape[0];
        columns= dataset.shape[1];
        for i in range(columns):
            for j in range(rows):
                dataset[i][j] = norm.pdf(dataset[i][j], self.m[i], self.s[i])*self.w;
        Posterior=dataset.sum(axis=1); # Row sum orior
        Denom=Posterior.var() * 2;  # Varienceee of the Row sums multi posterply by 2
        post=Posterior;     # orignal posterior without kerenl
        for k in range(len(Posterior)):
            post[k]= Posterior[k];
            Posterior[k] = np.exp(-(Posterior[k]**2)/Denom); # here we applied gaussian kernel to each posteriors
        
        ###step 6 started to calculate correntropyyy 
        corrs= list();
        corrfinal= list();
        for i in range(0,len(Posterior)-1):
            a=post[i];
            b=post[i+1];
            e=abs(b-a);
            c=1/len(Posterior);
            d=Posterior[0];## g(0) a guassian kernel coverted value of first posterior
            f=(d-(c*e))**(.5);
            corrs.append(f);
        
        corrfinal.append(Posterior[0]-((1/len(Posterior))*(post[0]-post[0])*(.5)));#accumodating the case of only first value to compensate equation 19
        for o in range(0,len(corrs)):
            corrfinal.append(corrs[o]);
        ####Step 6 ENDS
        ###Finding lower and upper corrs or noraml threshold upon results of step 6
        self.lowercorrnor=min(corrfinal);
        self.uppcorrnor=max(corrfinal);
        return [self.lowercorrnor,self.uppcorrnor]

#        if self.n_trained <= self.FM_grace_period and self.v is None: #If the FM is in train-mode, and the user has not supplied a feature mapping
#            #update the incremetnal correlation matrix
#            self.FM.update(x)
#            if self.n_trained == self.FM_grace_period: #If the feature mapping should be instantiated
#                self.v = self.FM.cluster(self.m)
#                self.__createAD__()
#                print("The Feature-Mapper found a mapping: "+str(self.n)+" features to "+str(len(self.v))+" autoencoders.")
#                print("Feature-Mapper: execute-mode, Anomaly-Detector: train-mode")
#        else: #train
#            ## Ensemble Layer
#            S_l1 = np.zeros(len(self.ensembleLayer))
#            for a in range(len(self.ensembleLayer)):
#                # make sub instance for autoencoder 'a'
#                xi = x[self.v[a]]
#                S_l1[a] = self.ensembleLayer[a].train(xi)
#            ## OutputLayer
#            self.outputLayer.train(S_l1)
#            if self.n_trained == self.AD_grace_period+self.FM_grace_period:
#                print("Feature-Mapper: execute-mode, Anomaly-Detector: execute-mode")
#        self.n_trained += 1

    #force execute KitNET on x
    def execute(self,attack):
        attack=pd.DataFrame(attack)
        attack=FE.clean_dataset(attack)
        attack=attack.drop(['index'], axis=1)
        
        # from sklearn.preprocessing import MinMaxScaler
        # rows = attack.shape[0];
        # columns= attack.shape[1];
        # for i in range(0,columns):
            # values = attack[i].values
            # values = values.reshape((len(values), 1))
            # scaler = MinMaxScaler(feature_range=(0, 1))
            # scaler = scaler.fit(values)
            # print('Min: %f, Max: %f' % (scaler.data_min_, scaler.data_max_))
            # attack[i] = scaler.transform(values)
        ro = attack.shape[0];
        col = attack.shape[1];
        for r in range(col):
            for t in range(ro):
                attack[r][t] = norm.pdf(attack[r][t], self.m[r], self.s[r])*self.w; 
        Post_attack=attack.sum(axis=1); # Row sum orior
        Denom2=Post_attack.var() * 2;  # Varienceee of the Row sums multi posterply by 2
        posterior_attack=Post_attack # original posterior of attacks without kerenl that is posterior_attack
        for p in range(len(Post_attack)):
            posterior_attack[p]=Post_attack[p];
            Post_attack[p] = np.exp(-(Post_attack[p]**2)/Denom2); # here we applied gaussian kernel to each posteriors
        corrs_attack= list();
        corrfinal_attack= list();
        for v in range(0,len(Post_attack)-1):
            a=posterior_attack[v];##this posterior_attack is without kernel
            b=posterior_attack[v+1];
            e=abs(b-a);##the subtraction of two petrior values without kernel in correntropy equation 
            c=1/len(Post_attack);
            d=Post_attack[0];##guassian kernel coverted value of first posterior g(0)
            fo= abs((d-(c*e)))
            f=fo**(.5);
            corrs_attack.append(f);
        corrfinal_attack.append(Post_attack[0]-((1/len(Post_attack))*(posterior_attack[0]-posterior_attack[0])*(.5)));#accumodating the case of only first value to compensate equation 19
        for u in range(0,len(corrs_attack)):
            corrfinal_attack.append(corrs_attack[u]);
        
        self.Ex_Mat = []                    
#        return (int(not(int(np.mean(self.drlist)<1))))
        return ((corrfinal_attack))

#        self.Ex_Mat = []                    
#        return (np.mean(corrfinal_attack))



            
            
            #        if self.v is None:
#            raise RuntimeError('KitNET Cannot execute x, because a feature mapping has not yet been learned or provided. Try running process(x) instead.')
#        else:
#            self.n_executed += 1
#            ## Ensemble Layer
#            S_l1 = np.zeros(len(self.ensembleLayer))
#            for a in range(len(self.ensembleLayer)):
#                # make sub inst
#                xi = x[self.v[a]]
#                S_l1[a] = self.ensembleLayer[a].execute(xi)
#            ## OutputLayer
#            return self.outputLayer.execute(S_l1)

 
#3524 training
#4405 normal-To v/alidate FPR 2-85
#13142 Attack - FNR 85-last
#================

path = "ComdInj_80203524440513142.csv" #event file to process.
packet_limit = np.Inf #the number of packets to process
file_path=path
grace = 3524# 120 events in a second
P = Flare(path,packet_limit,grace)
i = 0


start = time.time()
RES=[]#This can be optimize to increase the accuracy

#while True:
while True:
    i+=1
    if i % 1000 == 0:
        print(i)
    res = P.proc_next_packet()
    if res or res==0 or res==1:
        RES.append(res)
    if res == -1:
        break
RESs = RES    
stop = time.time()
l = RESs
  
# output list 
output = [] 
  
# function used for removing nested  
# lists in python.  
def reemovNestings(l): 
    for i in l: 
        if type(i) == list: 
            reemovNestings(i) 
        else: 
            output.append(i) 
  
# Driver code 
print ('The original list: ', l) 
reemovNestings(l) 
print ('The list after removing nesting: ', output) 

print("Complete. Time elapsed: "+ str(stop - start))






#
#
#
#mple = np.log(RESs[2:len(RESs)])
#
#
#
## Here we demonstrate how one can fit the RMSE scores to a log-normal distribution (useful for finding/setting a cutoff threshold \phi)
#from scipy.stats import norm
#benignSample = np.log(RESs[2:86])
##logProbs = norm.logsf(np.log(RESs[2:146]), np.mean(benignSample), np.std(benignSample))
#
## plot the RMSE anomaly scores
#print("Plotting results")
#from matplotlib import pyplot as plt
#from matplotlib import cm
#plt.figure(figsize=(10,5))
#fig = plt.scatter(range(1,len(mple)),mple[1:len(mple)],c=mple[1:len(mple)],s=5,cmap='RdYlGn')
#
##fig = plt.scatter(range(87,len(RESs)),RESs[87:],s=0.1,c=logProbs[87:],cmap='RdYlGn')
#plt.yscale("log")
#figbar=plt.colorbar()
#figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
#plt.show()
#3524 training
#4405 normal-To v/alidate FPR 2-85
#13142 Attack - FNR 85-last

#*********************************************************
fprlist=list();
drlist=list();
lowercorrnor=output[0]
uppcorrnor=output[1]
for x in range(2,881):
    if (output[x] >= lowercorrnor) or (output[x] <= uppcorrnor):    
        fprlist.append('0');
    else:
        fprlist.append('1');
for x in range(881,len(output)):
    if (output[x] <= lowercorrnor) or (output[x] >= uppcorrnor):
        drlist.append('1');
    else:
        drlist.append('0');
      
FPrate=(fprlist.count('1')/len(fprlist))*100
fnrate=(drlist.count('0')/len(drlist)) *100
errorr= (FPrate+fnrate)/2
drate=(drlist.count('1')/len(drlist)) *100    

#*********************************************************
#    lis=(lowercorrnor,uppcorrnor,FPrate,fnrate,errorr,drate,fprlist.count('1'),fprlist.count('0'),drlist.count('0'),drlist.count('1'))
#    with open("output.csv", "a") as f:
#        writer = csv.writer(f, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
#        writer.writerow(lis)
#    f.close