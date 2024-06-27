#!/usr/bin/env Rscript
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# A sample way of visualizing the output of qp-usdt.stp

library(tidyverse)

args = commandArgs(trailingOnly = TRUE)

pdf("qp_analysis.pdf", width = 11, height = 8, paper = "a4r")

data <- read_csv(args[1], col_types = "ccIiiiiii") %>%
    mutate(location = str_remove(location, ".*/")) %>%
    split(f = .$event, drop = TRUE)

ggplot(data$qp_lookup, aes(duration, fill = location)) +
    geom_histogram(bins = 200) +
    labs(title = "qp lookup", x = "Duration (ns)", y = "Count")

ggplot(data$qp_lookup, aes(duration, fill = location)) +
    geom_histogram(bins = 200) +
    labs(title = "qp lookup", x = "Duration (log ns)", y = "Count") +
    scale_x_log10()

ggplot(data$qp_lookup, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qp lookup", x = NULL, y = "Duration (ns)") +
    geom_boxplot(outliers = FALSE)

ggplot(data$qp_lookup, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qp lookup", x = NULL, y = "Duration (log ns)") +
    geom_boxplot() +
    scale_y_log10()

ggplot(data$qp_insert, aes(duration, fill = location)) +
    geom_histogram(bins = 200) +
    labs(title = "qp insert", x = "Duration (ns)", y = "Count")

ggplot(data$qp_insert, aes(duration, fill = location)) +
    geom_histogram(bins = 200) +
    labs(title = "qp insert", x = "Duration (log ns)", y = "Count") +
    scale_x_log10()

ggplot(data$qp_insert, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qp insert", x = NULL, y = "Duration (ns)") +
    geom_boxplot(outliers = FALSE)

ggplot(data$qp_insert, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qp insert", x = NULL, y = "Duration (log ns)") +
    geom_boxplot() +
    scale_y_log10()

ggplot(data$qp_getname, aes(duration, fill = location)) +
    geom_histogram(bins = 200) +
    labs(title = "qp getname", x = "Duration (ns)", y = "Count")

ggplot(data$qp_getname, aes(duration, fill = location)) +
    geom_histogram(bins = 200) +
    labs(title = "qp getname", x = "Duration (log ns)", y = "Count") +
    scale_x_log10()

ggplot(data$qp_getname, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qp getname", x = NULL, y = "Duration (ns)") +
    geom_boxplot(outliers = FALSE)

ggplot(data$qp_getname, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qp getname", x = NULL, y = "Duration (log ns)") +
    geom_boxplot() +
    scale_y_log10()

data$qp_compact %>%
    arrange(timestamp) %>%
    gather(id, value, 6:9) %>%
    ggplot(., aes(timestamp, value, color = id)) +
        labs(title = "qp chunk compaction", x = "Time since start (ns)", y = "Chunk Count") +
        geom_point() +
        geom_line(linetype = 2)

ggplot(data$qpmulti_query, aes(duration, fill = location)) +
    labs(title = "qpmulti query", x = "Duration (ns)", y = "Count") +
    geom_histogram(bins = 200)

ggplot(data$qpmulti_query, aes(duration, fill = location)) +
    labs(title = "qpmulti query", x = "Duration (log ns)", y = "Count") +
    geom_histogram(bins = 200) +
    scale_x_log10()

ggplot(data$qpmulti_query, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qpmulti query", x = NULL, y = "Duration (ns)") +
    geom_boxplot(outliers = FALSE)

ggplot(data$qpmulti_query, aes(location, duration, color = location)) +
    theme(axis.text.x = element_blank(), axis.ticks.x = element_blank()) +
    labs(title = "qpmulti query", x = NULL, y = "Duration (log ns)") +
    geom_boxplot() +
    scale_y_log10()

ggplot(data$qpmulti_write, aes(timestamp, duration, color = location)) +
    labs(title = "qpmulti write", x = "Time since start (ns)", y = "Duration (ns)") +
    geom_point() +
    geom_line(linetype = 2)

ggplot(data$qpmulti_snapshot, aes(timestamp, duration, color = location)) +
    labs(title = "qpmulti snapshot", x = "Time since start (ns)", y = "Duration (ns)") +
    geom_point() +
    geom_line(linetype = 2)

ggplot(data$qpmulti_marksweep, aes(timestamp, duration, color = location)) +
    labs(title = "qpmulti mark-sweep", x = "Time since start (ns)", y = "Duration (ns)") +
    geom_point() +
    geom_line(linetype = 2)

data$qpmulti_marksweep %>%
    gather(id, value, 6:9) %>%
    ggplot(., aes(timestamp, value, color = id)) +
        labs(title = "qpmulti mark-sweep", x = "Time since start (ns)", y = "Chunk Count") +
        geom_point() +
        geom_line(linetype = 2)

dev.off()
