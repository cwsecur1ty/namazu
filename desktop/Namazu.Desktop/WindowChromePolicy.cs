using System.Text.Json;

namespace Namazu.Desktop;

// The window protocol deliberately cannot name a file, URL, process or script.
internal static class WindowChromePolicy
{
    internal const string MessageType = "namazu-window";
    internal static bool IsAppDocument(string? value, Uri? origin)
    {
        return origin is not null && Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && uri.Scheme == origin.Scheme && uri.Host == origin.Host && uri.Port == origin.Port
            && uri.UserInfo.Length == 0 && uri.AbsolutePath == "/" && uri.Query.Length == 0;
    }

    internal static bool TryReadAction(string? message, string? source, string? currentSource, Uri? origin, out string action)
    {
        action = "";
        if (!IsAppDocument(source, origin) || !IsAppDocument(currentSource, origin)
            || message is null || message.Length > 256) return false;
        try
        {
            using var document = JsonDocument.Parse(message, new JsonDocumentOptions { MaxDepth = 3 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            var properties = root.EnumerateObject().ToArray();
            if (properties.Length != 3 || properties.Select(p => p.Name).Distinct().Count() != 3
                || !root.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.String
                || type.GetString() != MessageType
                || !root.TryGetProperty("version", out var version) || !version.TryGetInt32(out int number) || number != 1
                || !root.TryGetProperty("action", out var value) || value.ValueKind != JsonValueKind.String) return false;
            string? candidate = value.GetString();
            if (candidate is not ("menu" or "minimize" or "maximize" or "close" or "theme-light" or "theme-dark"
                or "pick-bruno-folder" or "pick-bruno-archive")) return false;
            action = candidate;
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) { return false; }
    }

    internal static string Bootstrap(Uri origin, object initialState)
    {
        string expectedOrigin = JsonSerializer.Serialize(origin.GetLeftPart(UriPartial.Authority));
        string state = JsonSerializer.Serialize(initialState);
        return $$$"""
        (() => {
          if (window !== window.top || location.origin !== {{{expectedOrigin}}} || location.pathname !== '/' || location.search) return;
          const allowed = new Set(['menu','minimize','maximize','close','theme-light','theme-dark','pick-bruno-folder','pick-bruno-archive']);
          let state = Object.freeze({{{state}}});
          const bridge = Object.freeze({version:1, get state(){return state;}, invoke(action){
            if (!allowed.has(action)) return false;
            window.chrome.webview.postMessage({type:'namazu-window',version:1,action});
            return true;
          }});
          Object.defineProperty(window,'NamazuNative',{value:bridge,configurable:false,writable:false});
          window.chrome.webview.addEventListener('message', event => {
            const data = event.data;
            if (data?.type === 'namazu-native-bruno-source' && data.version === 1
                && ['queued','cancelled','failed'].includes(data.status) && ['folder','archive'].includes(data.kind)) {
              window.dispatchEvent(new CustomEvent('namazu-native-bruno-source',{detail:Object.freeze({
                version:1,status:data.status,kind:data.kind,jobId:data.jobId || '',code:data.code || 'none'
              })}));
              return;
            }
            if (!data || data.type !== 'namazu-native-state' || data.version !== 1 || !data.state) return;
            state = Object.freeze(data.state);
            window.dispatchEvent(new CustomEvent('namazu-native-state',{detail:state}));
          });
        })();
        """;
    }
}
