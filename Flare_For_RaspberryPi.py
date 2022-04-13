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

        self.Detect = GMM(12,grace_period)



    def proc_next_packet(self):

        x = self.FE.get_next_vector()    

        if len(x) == 0:

            return -1 #Error or no input

        return self.Detect.process(x)  # will train during the grace periods, then execute on all the rest.

class FE:

    def __init__(self,file_path,limit=np.inf):

        self.path = file_path

        self.limit = limit

        self.parse_type = None #unknown

        self.curPacketIndx = 0

        self.csvin = None #used for parsing CSV file

        ### Prep input ##

        self.__prep__()





    def __prep__(self):

        ### Find file: ###

        if not os.path.isfile(self.path):  # file does not exist

            print("File: " + self.path + " does not exist")

            raise Exception()



        ### check file type ###

        type = self.path.split('.')[-1]



        ##If file is CSV 

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

            self.csvinf = open(self.path, 'rt', encoding="utf8")

            self.csvin = csv.reader(self.csvinf, delimiter=',')

             #move iterator past header



        else: 

            print("File format is not csv")

    def get_next_vector(self):

        ### Parse next input ###

        if self.parse_type == "csv":

            row = self.csvin.__next__()
                ### Choose the attributes ###

#            vsmc	=(float(row[18])+float(row[46]))/2

#            vsmb	=(float(row[16])+float(row[44]))/2

#            vsma	=(float(row[14])+float(row[42]))/2

            cpmc	=(float(row[12])+float(row[40]))/2

            cpmb	=(float(row[10])+float(row[38]))/2

            cpma	=(float(row[8])+float(row[36]))/2

#            vpmc	=(float(row[6])+float(row[34]))/2

#            vpmb	=(float(row[4])+float(row[32]))/2

            csmc	=(float(row[24])+float(row[52]))/2

            csmb	=(float(row[22])+float(row[50]))/2

            csma	=(float(row[20])+float(row[48]))/2

#            vpma	=(float(row[2])+float(row[30]))/2

#            vsac	=(float(row[17])+float(row[45]))/2

#            vsab	=(float(row[15])+float(row[43]))/2

#            vsaa	=(float(row[13])+float(row[41]))/2

            cpac	=(float(row[11])+float(row[39]))/2

            cpab	=(float(row[9])+float(row[37]))/2

            cpaa	=(float(row[7])+float(row[35]))/2

#            vpac	=(float(row[5])+float(row[33]))/2

#            vpab	=(float(row[3])+float(row[31]))/2

            csac	=(float(row[23])+float(row[51]))/2

            csab	=(float(row[21])+float(row[49]))/2

            csaa	=(float(row[19])+float(row[47]))/2

#            vpaa	=(float(row[1])+float(row[29]))/2

#            ria	=(float(row[28])+float(row[56]))/2

#            ra	=(float(row[27])+float(row[55]))/2

#            rf	=(float(row[25])+float(row[53]))/2

#            rfd	=(float(row[26])+float(row[54]))/2

            

        else:

            return []



        self.curPacketIndx = self.curPacketIndx + 1





        ### Extract Features

        try:

            return [cpma,cpmb,cpmc,csma,csmb,csmc,cpac,cpab,cpac,csaa,csab,csac]

        except Exception as e:

            print(e)

            return []



class GMM:

    def __init__(self,n,AD_grace_period):

        # Parameters:

        self.AD_grace_period = AD_grace_period

        self.n = n

        self.n_trained = 0 # the number of training instances so far

        self.n_executed = 0 # the number of executed instances so far

        self.Train_Mat= []

        self.Ex_Mat=[]

        self.count = 0

        self.count2=0

        self.window=120

        self.drlist=list()

        self.drlist=list();

        

    def process(self,x):

        if self.n_trained >= self.AD_grace_period: #If grace is in execute-mode

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

                return self.train(self.Train_Mat)

        self.n_trained += 1

        return

    def train(self,dataset):

        dataset=pd.DataFrame(dataset)

        pd.set_option('precision',7);

        self.m=dataset.mean(); # --- Mean (µ)

        self.s=dataset.std();  # --- Standard daviation (σ)

        self.v=self.s*self.s;            # --- Variance (𝜎^2)

        self.w=1/dataset.shape[1];

        rows = dataset.shape[0];

        columns= dataset.shape[1];

        for i in range(columns):

            for j in range(rows):

                dataset[i][j] = norm.pdf(dataset[i][j], self.m[i], self.s[i])*self.w;  # Calculate NORMDIST# muliplying with wieght step 3 of excel

#                dataset[i][j]=dataset[i][j]*self.w; # muliplying with wieght step 3 of excel

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

        ro = attack.shape[0];

        col = attack.shape[1];

        for r in range(col):

            for t in range(ro):

                attack[r][t] = norm.pdf(attack[r][t], self.m[r], self.s[r])*self.w;  # Calculate NORMDIST

#                attack[r][t]=attack[r][t]*self.w; # muliplying with wieght step 3 of excel

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

            f= (d-(c*e))**(.5);

            corrs_attack.append(f);

        corrfinal_attack.append(Post_attack[0]-((1/len(Post_attack))*(posterior_attack[0]-posterior_attack[0])*(.5)));#accumodating the case of only first value to compensate equation 19

        for u in range(0,len(corrs_attack)):

            corrfinal_attack.append(corrs_attack[u]);

            for x in range(0,len(corrfinal_attack)):

                if (corrfinal_attack[x] <= self.lowercorrnor) or (corrfinal_attack[x] >= self.uppcorrnor):

                    self.drlist.append('1');

                else:

                    self.drlist.append('0');

        return (int(not(int(np.mean(a)<1))))





 





path = "Power_Sys_Data.csv" #the csv file to process.

packet_limit = np.Inf #the number of lines to process

file_path=path

grace = 1200

P = Flare(path,packet_limit,grace)

i = 0





start = time.time()

RES=[]



while i< 2400:

    i+=1

    print(i)

    res = P.proc_next_packet()

    if res or res==0 or res==1:

        RES.append(res)

    if res == -1:

        break

RESs = RES    

stop = time.time()

print("Complete. Time elapsed: "+ str(stop - start))





