import TaskDetailView from "@/components/TaskDetailView";

export default async function TaskDetailPage({
  params,
}: {
  params: Promise<{ taskId: string }>;
}) {
  const { taskId } = await params;
  return <TaskDetailView taskId={taskId} />;
}
