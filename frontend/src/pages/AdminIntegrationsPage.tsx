import { Card, CardContent } from '@/components/ui/card';
import { useDocumentTitle } from '@/hooks/use-document-title';

export function AdminIntegrationsPage() {
  useDocumentTitle('Integrations');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Integrations</h1>
        <p className="text-muted-foreground">
          Connect third-party services
        </p>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center justify-center py-12">
            <div className="text-center space-y-3">
              <div className="text-6xl">🚧</div>
              <h3 className="text-lg font-semibold">Coming Soon</h3>
              <p className="text-sm text-muted-foreground max-w-md">
                Integration features are currently under development and will be available in an upcoming update.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
