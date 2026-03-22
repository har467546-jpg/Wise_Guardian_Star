import 'package:flutter_test/flutter_test.dart';
import 'package:situational_awareness_mobile/shared/models/app_models.dart';

void main() {
  test('task run decodes agent_orchestrate task type for mobile UI', () {
    final model = TaskRunModel.fromJson(
      <String, dynamic>{
        'id': 'task-agent-1',
        'task_type': 'agent_orchestrate',
        'status': 'running',
        'message': 'HAOR 正在执行',
        'progress': 55,
        'timing': <String, dynamic>{},
        'stage_timings': [],
      },
    );

    expect(model.taskType, TaskTypeModel.agentOrchestrate);
    expect(model.taskType.label, 'HAOR 执行');
  });
}
