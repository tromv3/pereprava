# Сборка «Переправы» для Linux (amd64). Интерфейс собирается заранее (frontend/dist),
# здесь только Go и Wails с WebKitGTK 4.1:
#   docker build -t pereprava-linux app/build/linux
#   docker run --rm -v "$PWD:/repo" pereprava-linux   (из корня репозитория)
FROM golang:1.27-bookworm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config >/dev/null \
 && rm -rf /var/lib/apt/lists/*
RUN go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1
WORKDIR /repo/app
CMD ["sh", "-c", "go vet ./... && go test ./... -count=1 && wails build -s -skipbindings -tags webkit2_41 -o pereprava-linux"]
