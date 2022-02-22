FROM golang:latest

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY articles.db .
COPY main.go .

ENV PORT 8000

RUN go build

CMD [ "./jwtEx.exe" ]