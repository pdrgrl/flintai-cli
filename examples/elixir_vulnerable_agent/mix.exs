defmodule VulnerableAgent.MixProject do
  use Mix.Project

  def project do
    [
      app: :vulnerable_agent,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:langchain, ">= 0.1.0"}
    ]
  end
end
