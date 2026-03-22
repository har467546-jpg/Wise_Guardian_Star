import 'dart:math' as math;

import 'package:flutter/material.dart';

enum AppWindowClass { compact, medium, expanded }

class AdaptiveLayoutInfo {
  const AdaptiveLayoutInfo._({
    required this.width,
    required this.windowClass,
    required this.horizontalPadding,
    required this.contentMaxWidth,
    required this.sectionGap,
  });

  factory AdaptiveLayoutInfo.fromWidth(double width) {
    if (width >= 840) {
      return AdaptiveLayoutInfo._(
        width: width,
        windowClass: AppWindowClass.expanded,
        horizontalPadding: 32,
        contentMaxWidth: 1120,
        sectionGap: 20,
      );
    }
    if (width >= 600) {
      return AdaptiveLayoutInfo._(
        width: width,
        windowClass: AppWindowClass.medium,
        horizontalPadding: 24,
        contentMaxWidth: 840,
        sectionGap: 18,
      );
    }
    return AdaptiveLayoutInfo._(
      width: width,
      windowClass: AppWindowClass.compact,
      horizontalPadding: 16,
      contentMaxWidth: 680,
      sectionGap: 16,
    );
  }

  final double width;
  final AppWindowClass windowClass;
  final double horizontalPadding;
  final double contentMaxWidth;
  final double sectionGap;

  bool get isCompact => windowClass == AppWindowClass.compact;
  bool get isMedium => windowClass == AppWindowClass.medium;
  bool get isExpanded => windowClass == AppWindowClass.expanded;

  int columns({
    required int compact,
    required int medium,
    required int expanded,
  }) {
    return switch (windowClass) {
      AppWindowClass.compact => compact,
      AppWindowClass.medium => medium,
      AppWindowClass.expanded => expanded,
    };
  }
}

typedef AdaptiveWidgetBuilder = Widget Function(
  BuildContext context,
  AdaptiveLayoutInfo layout,
);

class AdaptiveLayoutBuilder extends StatelessWidget {
  const AdaptiveLayoutBuilder({
    super.key,
    required this.builder,
  });

  final AdaptiveWidgetBuilder builder;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        return builder(
          context,
          AdaptiveLayoutInfo.fromWidth(constraints.maxWidth),
        );
      },
    );
  }
}

class AdaptiveGrid extends StatelessWidget {
  const AdaptiveGrid({
    super.key,
    required this.children,
    this.compactColumns = 1,
    this.mediumColumns = 2,
    this.expandedColumns = 3,
    this.spacing = 12,
    this.minChildWidth,
  });

  final List<Widget> children;
  final int compactColumns;
  final int mediumColumns;
  final int expandedColumns;
  final double spacing;
  final double? minChildWidth;

  @override
  Widget build(BuildContext context) {
    if (children.isEmpty) {
      return const SizedBox.shrink();
    }

    return AdaptiveLayoutBuilder(
      builder: (context, layout) {
        final configuredColumns = layout.columns(
          compact: compactColumns,
          medium: mediumColumns,
          expanded: expandedColumns,
        );
        final maxColumns = math.min(configuredColumns, children.length);
        final resolvedColumns = minChildWidth == null
            ? maxColumns
            : math.max(
                1,
                math.min(
                  maxColumns,
                  ((layout.width + spacing) / (minChildWidth! + spacing)).floor(),
                ),
              );
        final childWidth = (layout.width - ((resolvedColumns - 1) * spacing)) / resolvedColumns;

        return Wrap(
          spacing: spacing,
          runSpacing: spacing,
          children: [
            for (final child in children)
              SizedBox(
                width: childWidth,
                child: child,
              ),
          ],
        );
      },
    );
  }
}

class AdaptivePane extends StatelessWidget {
  const AdaptivePane({
    super.key,
    required this.leading,
    required this.trailing,
    this.breakpoint = 960,
    this.leadingWidth = 320,
    this.spacing = 16,
  });

  final Widget leading;
  final Widget trailing;
  final double breakpoint;
  final double leadingWidth;
  final double spacing;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth >= breakpoint) {
          final resolvedLeadingWidth = math.min(leadingWidth, constraints.maxWidth * 0.36);
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: resolvedLeadingWidth, child: leading),
              SizedBox(width: spacing),
              Expanded(child: trailing),
            ],
          );
        }

        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            leading,
            SizedBox(height: spacing),
            trailing,
          ],
        );
      },
    );
  }
}

class AdaptiveButtonGroup extends StatelessWidget {
  const AdaptiveButtonGroup({
    super.key,
    required this.children,
    this.breakpoint = 420,
    this.spacing = 12,
  });

  final List<Widget> children;
  final double breakpoint;
  final double spacing;

  @override
  Widget build(BuildContext context) {
    if (children.isEmpty) {
      return const SizedBox.shrink();
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth >= breakpoint) {
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (var index = 0; index < children.length; index++) ...[
                if (index > 0) SizedBox(width: spacing),
                Expanded(child: children[index]),
              ],
            ],
          );
        }

        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            for (var index = 0; index < children.length; index++) ...[
              if (index > 0) SizedBox(height: spacing),
              children[index],
            ],
          ],
        );
      },
    );
  }
}
