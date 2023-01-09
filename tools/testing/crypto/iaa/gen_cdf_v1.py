#!/usr/bin/env python3

import argparse
import numpy as np
import pandas as pd
from scipy import stats
import bokeh.resources as resources
from bokeh.plotting import figure, gridplot, save
from bokeh.models import ColumnDataSource
from pandas import Series
from bokeh.models import PanTool,ResetTool,HoverTool,WheelZoomTool,SaveTool,BoxZoomTool

import glob

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-d', '--dir', default='.', help='input and output data directory')
args = parser.parse_args()

files = glob.glob(f'{args.dir}/*_stats.csv')

for fl in files:
    try:
        df = pd.read_csv(fl, index_col=0)
        print(df)
    except IOError:
        print(f'{file} cannot be loaded into dataframe as csv file')
        exit(1)
    func_name = fl.split("_stats.csv")[0]
    df = df.dropna()
    pd.options.display.float_format = '{:,.0f}'.format

    # use kde to shrink the data size
    use_kde = True
    max_len = 100000
    if len(df) > max_len and use_kde:
        shrink_data = {}
        for column in df:
            kernel = stats.gaussian_kde(df[column].to_numpy())
            shrink_data[column]=kernel.resample(max_len)[0]
        df = pd.DataFrame(shrink_data)

    # sorting the original data
    df = df.transform(np.sort)
    df = df.reset_index(drop=True)

    names = df.columns
    total_p99 = df[names[-1]].quantile(0.99)
    df = df[df[names[-1]] < total_p99]

    cdata = {}
    for column in df:
        cdata[column] = df[column]
    cdata['percentile'] = df.index / len(df)
    data = ColumnDataSource(data=cdata)

    #tools = ["box_zoom", "pan", "wheel_zoom", "reset", "hover"]
    tools=[HoverTool(),BoxZoomTool(dimensions='height'), PanTool(dimensions='height'),  SaveTool(), ResetTool()]
    figures = []
    for column in df:
        if df.columns.get_loc(column) == 0:
            fig = figure(title=column, x_axis_label="Latency (us)", y_axis_label="CDF",
                    width=1000, height=500, tools=tools)
            y_range = fig.y_range
        else:
            fig = figure(title=column, x_axis_label="Latency (us)", y_axis_label="CDF",
                    width=1000, height=500, y_range=y_range, tools=tools)
        fig.line(column, 'percentile', line_width=2, color="blue", source=data)
        fig.x_range.start = min(df[column])
        fig.x_range.end = max(df[column])

        x = df[column]
        p50 = x.quantile(0.50)
        p75 = x.quantile(0.75)
        p98 = x.quantile(0.98)
        p99 = x.quantile(0.99)
        fig.line([p50, p50], [0, 1], color='red', width=3, legend_label=f'P50 = {p50:.0f}')
        fig.line([p75, p75], [0, 1], color='green', width=3, legend_label=f'P75 = {p75:.0f}')
        fig.line([p98, p98], [0, 1], color='purple', width=3, legend_label=f'P98 = {p98:.0f}')
        fig.line([p99, p99], [0, 1], color='black', width=3, legend_label=f'P99 = {p99:.0f}')
        figures.append(fig)

    p = gridplot(figures, ncols=1)
    save(p, filename=f"{func_name}_cdf.html", title="",
        resources=resources.INLINE)
