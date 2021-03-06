from graph_util import *

def plotThroughputLatency(dataFileNames, outputFileName, title=None):
    x_axis = "Throughput(Trx/s)"
    y_axis = "Latency(ms)"
    if (not title):
        title = "Throughput-Latency Graph"
    data = list()
    #data1 = list(("hotstuff.txt", "Hotstuff", 1, 2))
    names = ["Wendy", "Hotstuff"]
    i = 0
    for x in dataFileNames:
        data.append((x, names[i], 1, 2))
        i += 1
    plotLine(title, x_axis, y_axis, outputFileName,
             data, False, xrightlim=2000, yrightlim=20)

data = [(334, 2.99), (670, 2.98), (969, 3.09), (1264, 3.16), (1250, 4.02), (1308, 4.58), (1395, 6.5), (1380, 8.75)]
plotThroughputLatency(["data.txt", "hotstuff.txt"], "output")