package com.signature.scheme.tests;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import javax.swing.*;
import java.awt.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;

/**
 * Class allows to create charts for data stored in arrayLists
 */
public class Chart extends JFrame {

    public Chart(ArrayList<Double> arrayList, String path, String title) {
        initUI(arrayList, path, title);
    }

    private void initUI(ArrayList<Double> arrayList, String path, String title) {

        XYDataset dataset = createDataset(arrayList);
        JFreeChart chart = createChart(dataset, title);

        try {

            OutputStream out = new FileOutputStream(path + "/wykres - " + title + ".png");
            ChartUtilities.writeChartAsPNG(out,
                    chart,
                    1500,
                    1000);

        } catch (IOException ex) {

        }
    }

    private XYDataset createDataset(ArrayList<Double> arrayList) {

        XYSeries series = new XYSeries("");
        for (int i = 0; i < arrayList.size(); i = i + 10)
            series.add(i, arrayList.get(i));

        XYSeriesCollection dataset = new XYSeriesCollection();
        dataset.addSeries(series);

        return dataset;
    }

    private JFreeChart createChart(XYDataset dataset, String title) {

        String y = "";
        if (title == "Czas podpisywania") {
            y = "czas [ms]";
        } else if (title == "Czas weryfikacji") {
            y = "czas [ms]";
        } else if (title == "Pamięć sygnatur") {
            y = "pamięć [Byte]";

        }
        JFreeChart chart = ChartFactory.createXYLineChart(
                title,
                "Index",
                y,
                dataset,
                PlotOrientation.VERTICAL,
                true,
                true,
                false
        );

        XYPlot plot = chart.getXYPlot();

        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();
        renderer.setSeriesPaint(0, Color.RED);
        renderer.setSeriesStroke(0, new BasicStroke(2.0f));
        renderer.setSeriesShapesVisible(0, false);

        plot.setRenderer(renderer);
        plot.setBackgroundPaint(Color.white);

        plot.setRangeGridlinesVisible(true);
        plot.setRangeGridlinePaint(Color.BLACK);

        plot.setDomainGridlinesVisible(true);
        plot.setDomainGridlinePaint(Color.BLACK);

        chart.setTitle(new TextTitle(title,
                        new Font("Serif", java.awt.Font.BOLD, 18)
                )
        );

        return chart;

    }

}